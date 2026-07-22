# plan-v1.1 successor implementation status

This document records implementation evidence for the unfrozen `PLAN.md` successor. It does not
freeze or amend that specification. The immutable `plan-v1.0` tag remains historical. A contract is
`passed` only after every claimed clause runs successfully against the current successor topology;
a skip, xfail, simulation, predecessor result, or partial probe is never completion.

**Overall status: implementation qualified on the pinned host; specification still unfrozen.**
`plan-v1.1` has 78 acceptance contracts and uses a schema-v3 `live-v3.json` receipt. The final
current-tree automated suite completed with **814 passed and 8 skipped**. Skipped nodes were not
counted as passes. The installed qualifier from the exact reviewed wheel separately completed all
18 receipt-bound target-host/live gates and minted the production receipt. The deterministic/host
suite and installed qualification together provide passing evidence for all 78 contracts; the
18-gate receipt alone is deliberately not described as 78/78 conformance.

The repaired topology is live-qualified. The fixed root-owned author broker preserves Ubuntu's
AppArmor restriction while leaving Codex's one mandatory inner Bubblewrap transition available.
Pinned Claude accepted the closed plain-object review-wrapper schema with its nested `anyOf`,
returned top-level `structured_output.review`, and passed the exact managed-boundary, selection,
retry, and account-isolation checks. The receipt makes production execution eligible only for its
exact binding and validity window. `PLAN.md` nevertheless remains unfrozen because its documented
issue/PR, complete-review, merge, and annotated `plan-v1.1` tag workflow has not been completed.

## Detected environment

| Component | Detected | Pinned target | Result |
|---|---|---|---|
| OS | Ubuntu 26.04 LTS (Resolute), x86_64 | Ubuntu 26.04, x86_64 | compatible |
| Kernel | Linux 7.0.0-28-generic | reviewed Ubuntu 26.04 kernel | compatible; probes passed |
| Python | CPython 3.14.4 | CPython 3.14.4 | compatible |
| Git | 2.53.0 | 2.53.0 | compatible |
| Bash | 5.3.x | 5.3.x | compatible |
| Bubblewrap | upstream 0.11.1; package `0.11.1-1ubuntu0.1`; `/usr/bin/bwrap`, root:root, mode `0755`, SHA-256 `0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0` | exact patched non-setuid build | compatible; provenance and negative probes passed |
| systemd user manager | systemd 259; user manager running | transient user services on 259 | compatible; lifecycle/resource probes passed |
| Codex CLI | 0.144.6 | 0.144.6 | passed; non-model probes plus paid first/resume turns proved exact-ID continuity, requested model/effort evidence, Git-less cwd/add-dir policy, fixed-manager/inner-Bubblewrap composition, workspace-write/no-network/control denial, and instruction isolation |
| Claude Code | 2.1.215 | 2.1.215 | passed; private account-file authentication, exact model/effort diagnostic binding, closed review wrapper, remote nested-`anyOf` acceptance, retry ceilings, tool isolation, and managed-boundary attestation all passed |
| Namespace/runtime | user/PID/IPC/UTS/network namespaces, full tmpfs, PID 1 supervisor | required | passed; user-service validation/Git/critic boundaries and fixed system-manager author boundary proved resource limits, cleanup, AppArmor-preserving inner sandbox composition, process isolation, and complete export |

`PLAN.md` remains the explicit unfrozen `plan-v1.1` successor. The immutable `plan-v1.0` tag at
`6b16d5601b1aad7689d18cbd3802c9244c68444f` is unchanged. The standard Codex and Claude CLI file
logins were reused through the private default profile without printing secret content, a setup
token, or an `agent-loop auth` import step. The reviewed managed-Claude boundary and fixed author
broker are installed and qualified. A private schema-v3 receipt now exists for the exact qualified
binding; it does not freeze the specification or replace repository change control.

## Phase checklist

- [x] Phase 1: canonical subject runtime — the ignore-independent manifest, confined filesystem,
  hardened Git reader, policy, Git-less materialization, and diagnostic projection passed their
  current-tree unit, integration, adversarial, and host coverage.
- [x] Phase 2: containment runtime — validation/Git/critic user-service boundaries and the fixed
  administrator-installed author broker passed protocol, provenance, resource, cleanup, complete
  export, process-isolation, and real inner-Codex-sandbox qualification.
- [x] Phase 3: fake agents and deterministic control plane — mutation/process, credential
  bootstrap/refresh/crash recovery, verdict/protocol/retry, deadline, cap, stall, and hostile-data
  families passed in the final automated suite.
- [x] Phase 4: pinned real-CLI integration — the installed qualifier proved exact Codex first/resume
  behavior, Claude account-file review, model/effort evidence, remote review-wrapper compatibility,
  managed-boundary attestation, and every one of the 18 receipt-bound gates in one clean run.
- [x] Phase 5: serial loop and usability — `run`, `status`, `show`, `auth`, `qualify`, dry-run,
  strict configuration, confirmation, artifacts, receipt enforcement, wheel packaging, one-time
  administrator installation, and normal no-extra-auth UX all have passing evidence.

The implementation is qualified on the pinned host. The specification remains intentionally
unfrozen only until its separate repository change-control and immutable-tag steps complete.

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
| 8 | Network split | `tests/host/test_network_boundary.py::test_008_network_split_for_no_network_role` plus the installed Codex and Claude qualification probes | passed |
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
| 30 | Process introspection | all four `test_030_*` cases in `tests/host/test_process_isolation.py`, the `NSpid` normalization regressions in `tests/unit/test_qualification.py`, and the installed author probe's exact visible-process/ancestry checks | passed |
| 31 | Sanitized Codex home | all `test_031_*` cases in `tests/integration/test_codex_client.py` | passed |
| 32 | Codex auth isolation | deterministic credential/barrier tests plus the installed first/resume command probes proved the transaction credential absent from model-command environment/output and `/control/codex-home/auth.json` unreadable | passed |
| 33 | Custom profile | pinned profile parsing/negative tests plus installed first/resume probes proved bounded workspace writes, inert read-only `.git` guard, no network, and control/artifact denials through the fixed manager and inner Bubblewrap | passed |
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
| 49 | Managed Claude boundary | deterministic closed-policy/helper tests plus the installed paid critic proved the exact root-owned closure, account-file path, process set, tool denial, child-environment scrub, and the helper's full literal or pinned exact `[REDACTED]` attestation marker | passed |
| 50 | Hostile Claude project config | `tests/integration/test_claude_client.py::test_050_hostile_claude_project_config_is_not_in_environment_or_cwd` | passed |
| 51 | Retry budget | deterministic process-local pinned-CLI probes proved one structured correction, local contradiction without undeclared retry, exactly one initial API attempt plus two API retries, no retry watchdog, and typed exhaustion; the installed critic used the same bound configuration | passed |
| 52 | Schema semantics | Draft-07 schema parity/contradiction tests and the installed remote call proved the closed `structured_output.review` wrapper with nested `anyOf`; independent local validation rejected invalid verdict, field, range, and cross-field combinations | passed |
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
| 64 | Model record | bounded rollout/API-diagnostic parsers, mismatch regressions, and the installed first/resume/review sequence bound requested and client-observed model/effort values without treating them as server attestation | passed |
| 65 | Git-less first turn and resume | installed paid first/resume calls used one exact thread through the fixed manager with the same empty cwd, `/workspace` add-dir, outside-Git flag, approval/profile policy, and successful exact command evidence | passed |
| 66 | Project-instruction isolation | non-model prompt-input probes and installed hostile-marker first/resume turns proved project instruction files and every pinned system-skill/extension surface absent from the effective control context | passed |
| 67 | Auth refresh persistence and serialization | final deterministic account-file coverage proved global lock order, validation, atomic refresh reconciliation, pair-transition recovery, disposable source probes, generation barriers, and concurrent-run serialization; the installed qualification exercised the combined transaction | passed |
| 68 | Withheld semantic delta | `tests/unit/test_prompts.py` (`test_068_*`) and both counterfactual `test_068_*` cases in `tests/integration/test_runner.py` | passed |
| 69 | Validation-log exfiltration | `tests/adversarial/test_declassify.py::test_069_validation_log_exfiltration` and the exact/split/base64/lowercase-hex/uppercase-hex parameterizations of `tests/integration/test_runner.py::test_069_secret_forms_never_cross_validation_to_either_agent` | passed |
| 70 | Diagnostic patch correctness | `tests/unit/test_diagnostic_patch.py::test_070_projection_exactly_covers_all_manifest_change_shapes_and_hashes` | passed |
| 71 | Transient-service lifecycle | user-service lifecycle tests and the installed qualification proved declared cleanup/resource behavior for validation, Git, critic, and the distinct fixed author-manager job | passed |
| 72 | Claude account-auth isolation | deterministic refresh/artifact coverage and the installed paid critic proved only the private `.credentials.json` transaction under private `CLAUDE_CONFIG_DIR`, `HOME=/nonexistent`, no normal-path token/API-key environment state, child scrubbing, and no credential output | passed |
| 73 | Codex control-context isolation | parser/marker guards plus installed first/resume turns proved all five pinned system skills and plugin/app/goal/personality/collaboration surfaces and associated tools absent | passed |
| 74 | Pinned selection-evidence adapters | malformed/drift/reroute regressions plus one installed real first/resume/review sequence proved the exact descriptor-confined Codex rollout and bounded Claude API-diagnostic parsers | passed |
| 75 | Live receipt lifecycle | deterministic binding/privacy/expiry/invalidation tests plus the sole installed issuer minted the private schema-v3 receipt only after every one of the 18 required gates passed | passed |
| 76 | Fixed author-manager and inner sandbox composition | installed-artifact provenance, peer/descriptor policy, direct-manager denial, privilege drop, AppArmor-preserving namespace, exact inner Bubblewrap ancestry/profile, cleanup, and real paid first/resume turns all passed | passed |
| 77 | Lazy bootstrap and smooth authentication | deterministic coverage proved absent-default import, local-only status, no routine auth command, strictly newer vendor-login adoption, stale rollback prevention, paired crash recovery, and interruption-safe source probes; installed qualification reused the default pair without project auth setup | passed |
| 78 | Claude wire/local contract | deterministic/local probes and the installed paid critic proved the exact canonical Draft-07 plain-object root, required `review` wrapper, nested `anyOf`, no `if`/`then`, remote acceptance, top-level `structured_output.review`, diagnostic binding, and stricter independent local rejection | passed |

All 78 rows now have passing evidence. That result combines the **814 passed, 8 skipped** final
automated suite with the installed qualifier's 18 successful target-host/live gates. The skipped
nodes are recorded honestly and are not counted as passing evidence. Conversely, the live receipt
attests only its named 18 gates and is not, by itself, evidence for the other 60 contracts or for
static analysis, packaging quality, or target-project correctness.

## Implementation decisions within non-normative freedom

- Runtime implementation uses the Python standard library. Total local parsers enforce the
  versioned JSON documents at runtime; the development suite additionally validates each document
  against its declared dialect. The critic contract is Draft 7 because the pinned Claude 2.1.215
  CLI rejects a Draft 2020-12 metaschema before launch; all other packaged schemas remain Draft
  2020-12. The remote-compatible document has a closed plain-object root containing only a required
  `review` property; that value uses the nested LGTM/REVISE/BLOCKED `anyOf`. The runner accepts only
  the exact `envelope["structured_output"]["review"]` path, revalidates the complete wrapper, and
  applies independent stricter local semantics to the review. An incoherent verdict can receive
  only Claude's one declared wire-schema correction; a wire-valid local contradiction is terminal.
- Pinned Codex 0.144.6 does not publish positive model/effort facts in its public exec JSONL. The
  adapter rejects that stream's exact server-reroute error signal, then binds the successful thread
  to one private per-thread rollout. Descriptor-confined, byte/event-bounded traversal accepts only
  the pinned durable item types and complete task lifecycles; it extracts the client-resolved
  model/effort, requires the prior rollout bytes to remain an exact SHA-256-witnessed prefix plus
  one new turn on resume, and rejects disagreement with the request. Raw rollout contents and the
  in-memory prefix witness are not copied into retained run evidence.
- Canonical manifest and blob hashes use SHA-256. Canonical manifest bytes use a versioned,
  length-prefixed binary encoding over raw path and symlink-target bytes. JSON artifacts retain
  base64 identity plus deterministic safe display strings.
- Git source authority, reviewed mount roots, and retained closure traversal are descriptor-bound.
  Component-wise `openat2`/no-follow checks, stable metadata witnesses, exact-fd Bubblewrap binds,
  and private read-only closure snapshots close pathname replacement races before launch.
- An inherited procfs across nested PID namespaces can enumerate numeric directories with
  ancestor-namespace labels. The author qualification takes stable before/after `/proc` snapshots,
  maps every entry by the final `NSpid` component, remaps `PPid` labels through that closed table,
  and fails on missing, duplicate, or unstable mappings. This normalizes identity without widening
  the exact visible-process or ancestry allowlist.
- Pinned Claude 2.1.215 may rewrite the reviewed SessionStart helper's assignment-shaped `scrub=1`
  suffix to the exact `[REDACTED]` spelling in verbose stderr. The attestation parser admits only the
  full literal marker or that one exact redacted marker. The root-owned helper/policy closure and
  static helper probe establish the condition behind the marker; prefixes and alternative
  redaction spellings are rejected.
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
- Every newly observed Codex or Claude account-file credential generation is checked against
  generated configuration and the complete retained tree before the transaction is accepted. Final
  reconciliation repeats that barrier over all historical/current generations before credential
  completion. When the default stores are wholly absent, the first ordinary preflight may import
  only the authorized operator's active standard CLI credential files. A later valid default pair
  may adopt only a strictly newer parser-valid generation from those exact paths after probing it in
  disposable private state; stale/equal/unsafe/failed probes never replace durable state. Partial or
  invalid managed state is never implicitly repaired. The pinned status probes establish local CLI
  acceptance, not remote token validity.
- Credential-tainted or unclassifiable evidence is whole-run withheld. A zero-byte per-run latch in
  a private, structurally separate control directory is persisted before erasure; a reentrant
  process lock plus per-run `flock` serializes the latch with artifact and production retained-tree
  operations. Reopen replays interrupted erasure and refuses access. A transient marker failure is
  retried after best-effort erasure; even persistent marker failure still attempts complete erasure
  and returns a fatal credential-refresh error.
- The schema-v3 live receipt names all 18 receipt-bound gates. Only the installed, version-matched
  `agent-loop qualify --live --accept-paid` command may issue a production receipt; repository
  pytest sessions are diagnostic and cannot mint one. The installed qualifier rejects failures,
  timeouts, incomplete phases, stale observations, selector mismatch, or changed author-manager,
  install/runtime, or managed-Claude closure before issuance. Older receipts and incomplete
  schema-v3 attempts are not accepted or migrated.
- Rename diagnostics are deterministic delete/create pairs with matching kind, mode, and content
  identity; canonical manifests do not claim Git rename history.

## Completed evidence and requalification

The qualified artifact is the wheel named below as bound by the root-owned install record and
private receipt:

```text
dist/agent_loop-1.1.0-py3-none-any.whl
```

This document deliberately does not embed that wheel's digest: it is itself packaged into the
wheel, so doing so would be a self-referential and immediately stale claim. The installer records
the exact digest in `/etc/agent-loop/author-service-install.txt`, and the qualifier binds it into the
private receipt. That exact wheel was installed into both the unprivileged CLI environment and the
reviewed root-owned author-service closure before the successful paid qualification. The sole
production issuer is the installed command:

```bash
agent-loop qualify --live --accept-paid
```

Repository-local pytest remains useful for deterministic, adversarial, host, and diagnostic
real-CLI coverage, but it cannot mint a production receipt. The installed qualifier reruns the
production probes and binding checks without requiring the repository `tests/` tree.

The current private receipt has these non-secret structural facts; inspect the live private file
for its exact digest and timestamps rather than copying volatile values into packaged documentation:

```text
path     ${XDG_STATE_HOME:-$HOME/.local/state}/agent-loop/capabilities/live-v3.json
schema   3
mode     0600
gates    18
validity at most seven days
```

Re-run the installed qualifier after expiry or whenever any receipt-bound host, executable,
runtime, author-manager, managed-Claude, credential identifier, model, or effort fact changes. It
must again complete every gate; a partial or failed attempt never becomes a receipt. Review the
printed paid scope before passing `--accept-paid`.

Normal runs require no project-specific authentication command. Existing standard file-backed
Codex and Claude sign-ins are reused automatically. If a vendor status command reports sign-out, or
an actual model request returns the runner's exact vendor-session-ended diagnostic, run only that
vendor's native login once and rerun the original command. Do not run an `agent-loop auth` import
step. Generic process/probe failures are not evidence that reauthentication is needed. The optional
`agent-loop auth status` and `auth init --repair` commands remain advanced local diagnostics and
integrity recovery, respectively.

The implementation has no remaining qualification prerequisite on this pinned host. Freezing the
specification is a distinct repository-governance action: open and review the required issue/PR,
merge the final document, and create the annotated immutable `plan-v1.1` tag. Until then the correct
description is **implementation qualified; specification unfrozen**.

## Check log

| Date | Command | Result |
|---|---|---|
| 2026-07-19–20 | predecessor deterministic, host, non-model CLI, wheel, and two combined paid attempts | useful historical repair evidence only; no receipt was written and the successor topology supersedes the aggregate counts |
| 2026-07-21 | current Codex and Claude standard-login status checks | passed without exposing secret content; Codex uses ChatGPT file auth and Claude uses an active claude.ai subscription login |
| 2026-07-21 | pinned Claude 2.1.215 `auth status --json` with only a private copy of `.credentials.json`, private `CLAUDE_CONFIG_DIR`, and nonexistent home | passed without a model call; supports the no-setup-token default path |
| 2026-07-21 | explicitly authorized successor combined qualification | failed closed; Claude returned pre-inference HTTP 400 for conditional schema keywords and Codex inner Bubblewrap was denied beneath the former outer user namespace; no receipt was written |
| 2026-07-21 | final current-tree automated suite | **814 passed, 8 skipped**; skips were not counted as passes, and live evidence came from the installed qualifier |
| 2026-07-21 | reviewed wheel build and installed-boundary replacement | passed; the exact wheel digest was recorded in the root-owned install record and receipt binding |
| 2026-07-21 | installed `agent-loop qualify --live --accept-paid` | passed all 18 target-host/live gates: fixed broker plus inner Codex sandbox first/resume, `NSpid`-normalized ancestry, account isolation, exact full-or-`[REDACTED]` managed-Claude attestation, retry/selection evidence, and remote plain-root/nested-`anyOf` review wrapper |
| 2026-07-21 | schema-v3 receipt | minted mode `0600` with an at-most-seven-day validity window and exact artifact/host binding |

The correct status is **implementation qualified on the pinned host; `plan-v1.1` remains unfrozen
pending its issue/PR/review/merge/tag workflow**.
