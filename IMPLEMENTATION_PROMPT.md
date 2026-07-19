# Codex implementation prompt for `plan-v1.0`

Use the prompt below from the repository root. It is an execution prompt, not a replacement for [`PLAN.md`](PLAN.md). `PLAN.md` is the frozen normative specification and wins if this companion prompt is incomplete or ambiguous.

---

You are the lead implementation engineer for this repository. Implement the frozen version 1 specification in `PLAN.md` as a production-quality, security-sensitive Python application.

## Mission

Deliver a working `agent-loop` CLI that runs a bounded Codex-author / Claude-critic coding loop exactly as specified by `plan-v1.0`.

Do not merely analyze the plan, produce another plan, or stop after scaffolding. Work through the implementation phases in order, write the code and tests, run the applicable checks, diagnose failures, and continue until the version-1 completion criteria are met or a genuine external prerequisite makes further progress impossible.

The intended outcome is a containment-first local execution runtime with an agent loop on top. Treat it accordingly; this is not a small shell wrapper.

## Source of truth and precedence

1. Read `PLAN.md` completely before editing anything.
2. Treat its frozen contracts, security boundaries, state machine, exit codes, pinned platform matrix, phases, and all 72 acceptance tests as normative.
3. Treat this prompt as execution guidance only. If it conflicts with `PLAN.md`, follow `PLAN.md` and record the discrepancy.
4. Do not edit `PLAN.md`. A required normative change is not an implementation detail: stop that affected path, explain the conflict precisely, and propose a successor-spec change without weakening version 1.
5. Preserve existing user changes. Inspect Git status and diffs before editing; never overwrite unrelated work.
6. Use only official OpenAI, Anthropic, Git, Linux, Bubblewrap, systemd, Python, and Ubuntu documentation when exact behavior needs verification. The pinned CLI behavior and successful local capability probes recorded in `PLAN.md` take precedence for this version.

## Operating authority and prohibitions

You are authorized to create and edit project files, run local formatting/static-analysis/unit tests, and run non-destructive containment probes needed to implement the repository.

You are not authorized to:

- weaken, bypass, stub out, or silently downgrade a security contract so a test passes;
- edit the frozen plan;
- commit, reset, clean, push, open or merge a PR, publish a package, or otherwise mutate a remote;
- use `danger-full-access`, `--dangerously-bypass-approvals-and-sandbox`, an unbounded shell loop, or an alternate unreviewed sandbox backend;
- fetch packages or run installers without first reporting the exact missing dependency and using the repository's declared, reviewable dependency workflow;
- expose, print, copy into artifacts, or pass to model-generated commands any credential, token, keychain state, cloud configuration, socket, or ambient user configuration;
- make paid/live Codex or Claude model calls until the fake-agent and containment gates pass and the operator explicitly supplies the required credential identifiers and confirms live smoke testing;
- claim a check passed when it was skipped, simulated, or blocked by the host environment.

Use reasonable implementation judgment inside the frozen interfaces. Do not pause for routine choices that can be made safely and reversibly. Ask the operator only when a required project-specific input is absent or an action needs authority beyond the scope above.

## Required working method

### 1. Orient and establish traceability

Before implementation:

- inspect the repository, Git status, current platform, kernel, Python, Git, Bubblewrap package/mode, systemd user-service availability, Codex version, and Claude version;
- compare the environment with the pinned matrix without changing the host;
- read every section of `PLAN.md`, including the historical review dispositions, limitations, and acceptance tests;
- create `docs/IMPLEMENTATION_STATUS.md` containing:
  - the detected environment and compatibility result;
  - a phase checklist matching phases 1 through 5;
  - a table mapping acceptance tests 1 through 72 to test names/files and status (`pending`, `passed`, `blocked`, never `assumed`);
  - decisions made within non-normative implementation freedom;
  - external prerequisites and exact reproduction commands for any block.

Keep that status document current as work proceeds. It is evidence, not a substitute for executable tests.

### 2. Establish a maintainable Python project

Create a conventional `src`-layout, `pipx`-installable Python package with an `agent-loop` console entry point. Prefer a minimal dependency set and standard-library primitives where they are adequate. Pin supported versions and hashes through the project's chosen reproducible dependency mechanism.

Unless existing code establishes a better layout, use cohesive modules along these boundaries:

```text
src/agent_loop/
├── cli.py                    # run/status/show commands and stable exits
├── config.py                 # strict project/run configuration
├── constants.py             # pinned versions, limits, schema versions
├── errors.py                 # typed stop reasons and stable exit categories
├── state_machine.py          # monotonic fatal latch and convergence logic
├── models.py                 # immutable internal domain models
├── manifests.py             # SubjectManifest, canonical encoding, fingerprints
├── filesystem.py            # openat2 confinement and safe atomic operations
├── artifacts.py             # private crash-consistent run evidence
├── git_source.py            # hardened, sandboxed committed-tree reader
├── diagnostic_patch.py      # manifest-native bounded human projection
├── service.py               # transient-systemd lifecycle and cgroup checks
├── sandbox.py               # Bubblewrap policy and trusted supervisor protocol
├── sandbox_init.py          # in-namespace materialize/run/kill/scan/export
├── validation.py            # baseline/current checks and mutation detection
├── declassify.py            # raw-log separation and critic-safe evidence
├── credentials.py           # locked Codex transaction and Claude token adapter
├── schemas.py               # local JSON Schema validation and semantic checks
├── prompts.py               # bounded hostile-data-safe author/critic prompts
├── codex_client.py           # pinned JSONL exec/resume protocol
├── claude_client.py          # fresh tool-disabled structured critic protocol
├── progress.py               # exact normalized non-success fingerprint
└── runner.py                 # serial orchestration only after components prove safe
```

Separate pure policy/serialization code from OS side effects. Make privileged or security-sensitive transitions explicit and testable. Avoid a generic “utils” dumping ground.

Add:

- `pyproject.toml` with the CLI entry point, supported Python version, build metadata, test configuration, formatting, linting, and strict type checking;
- `tests/unit`, `tests/integration`, `tests/adversarial`, `tests/fakes`, and narrowly scoped fixtures;
- JSON Schema files or versioned schema constants for run manifests, subject manifests, sandbox protocol messages, validation evidence, and critic output;
- a concise `README.md` covering purpose, pinned support matrix, installation, safe credential provisioning, basic commands, security warnings, and development checks;
- `.gitignore` entries for build/test caches only—never rely on ignore rules for subject correctness.

Do not add an `AGENTS.md`, plugin, hook, MCP server, hosted component, dashboard, alternate backend, linked worktree mode, direct-checkout mode, Git-history view, or run-level resume command in version 1.

### 3. Implement phase gates in order

Do not integrate real agent CLIs before the containment runtime and fake-agent control plane pass their applicable tests.

#### Phase 1 — Canonical subject runtime

Implement first:

- the versioned `SubjectManifest` as the sole authoritative state;
- lossless raw path-byte identity, safe display strings, canonical ordering, versioned deterministic encoding, stable collision-resistant content hashes, and subject fingerprints;
- normalized regular/non-executable, regular/executable, and symlink entries only;
- content-addressed blobs, exact literal symlink targets, metadata stripping/rejection, complete ignore-independent scanning, hard-link rejection, and special-file rejection;
- Linux `openat2` confinement using `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, with a narrowly reviewed wrapper and fail-closed availability probe;
- directory-relative, no-follow, `O_CLOEXEC` operations; atomic write/fsync/rename/fsync persistence; mode `0700` directories and `0600` files independent of caller `umask`;
- `protected_paths`, `discard_only_paths`, and predeclared opaque non-semantic policy with semantic-by-default behavior;
- the hardened no-network Git object reader for committed `HEAD`, NUL-safe `ls-tree`/`cat-file --batch`, environment scrubbing, bounded output, repository-shape rejection, and zero writes to the source checkout or Git metadata;
- private Git-less materialization and the manifest-native diagnostic patch renderer.

Git status, patches, ignore rules, indexes, and worktrees are never authoritative. Do not use checkout, worktree, reset, clean, filters, textconv, external diffs, hooks, fsmonitor, credential helpers, pagers, editors, remotes, or a writable Git control plane.

Phase 1 is complete only when its unit and adversarial tests prove create/modify/delete/rename-equivalent/binary/mode/symlink/ignored-file coverage, repository immutability, hostile Git neutralization, arbitrary path handling, metadata normalization, and confinement races.

#### Phase 2 — Containment prototype

Implement the one permitted backend:

- patched non-setuid Ubuntu Bubblewrap plus transient `systemd-run --user` services;
- a trusted `sandbox-init` as the initial Bubblewrap process;
- a fresh explicitly sized full tmpfs workspace, not an overlay;
- pre-opened bounded manifest/blob input and export channels;
- materialize → launch → wait → kill all descendants → prove empty → complete scan/export → exit;
- exact service properties from `PLAN.md`, including `Type=exec`, `KillMode=control-group`, `SendSIGKILL=yes`, bounded `TimeoutStopSec`, `OOMPolicy=kill`, `CollectMode=inactive-or-failed`, memory/task/runtime/file-size/file-descriptor/core limits;
- process-group handling only as supplemental cleanup, never as the containment boundary;
- separate author, validation, critic-control, and hardened-Git policies;
- no network for model-generated commands, validation, Git, or critic tools;
- normal host egress only for the trusted Codex and Claude control binaries;
- no host home, credentials, sockets, artifact tree, control state, mutable caches, or unreviewed toolchain mounts in untrusted execution paths;
- denial of `/proc` environment/fd/memory inspection, ptrace, `process_vm_readv`, `pidfd_getfd`, core dumps, and inherited-descriptor leakage;
- byte/file/output/deadline bounds and cgroup emptiness verification on success, failure, timeout, OOM, interrupt, fork, daemonization, and new sessions.

The Bubblewrap package probe must check the Ubuntu package revision, upstream version, owner, mode, setuid bit, and binary hash as specified. Do not claim a hard inode quota. If the host cannot prove this backend, preserve completed portable/pure code but report the integration tests as blocked; do not substitute Docker, `codex sandbox`, an overlay, or a weaker process wrapper.

Implement pristine-base and post-candidate validation using the same full-tmpfs topology. Validation must operate on a separately materialized frozen subject, retain a bounded sensitive raw log locally, export a mutation manifest, and never modify the authoritative subject.

#### Phase 3 — Fake agents and deterministic control plane

Before real Codex or Claude integration, implement configurable fake executables that can deterministically:

- emit valid and malformed Codex JSONL events and thread IDs;
- mutate allowed, protected, ignored, secret-like, oversized, binary, symlink, hard-link, and special paths;
- fork or daemonize children, hang, exceed output/resource limits, exit nonzero, refresh a fake credential, and die mid-refresh;
- emit every valid and invalid Claude envelope/verdict/schema combination;
- return late, exhaust turns/retries, quote hostile instructions, repeat an exact state, or produce a successful revision sequence.

Use the fakes to implement and prove:

- fatal-first, monotonic-clock state handling where a latched fatal condition can never be cleared;
- stable exit codes `0`, `10` through `18` and every fine-grained mapping in `PLAN.md`;
- success on the final allowed round, but never after a deadline or integrity failure;
- exact normalized non-success stall detection;
- private, crash-consistent artifacts and bounded streams;
- per-source/run locking and account-scoped credential locking;
- the Codex credential copy/validate/fsync/atomic-promote/crash-recovery transaction without logging secret bytes;
- dedicated Claude token injection without ambient keychain or API-key state;
- baseline/current validation classification and protected-harness behavior;
- raw validation logs versus separately declassified, approval-eligible structured evidence;
- semantic-delta completeness, bundle byte/token/file/field budgets, and fail-closed withheld-content/evidence handling;
- versioned critic schemas, top-level envelope extraction, local schema revalidation, semantic cross-field validation, and normalized return-path prompts;
- hostile source/log/review text treated exclusively as delimited data.

Never grep prose for approval. Only a locally revalidated `structured_output` object can supply `LGTM`, and it is semantically valid only when every success predicate in `PLAN.md` is true.

#### Phase 4 — Pinned real-CLI integration

Only after phases 1 through 3 pass, add adapters for the pinned CLIs.

For Codex:

- build the sanitized account-transaction `CODEX_HOME` exactly as specified, with no ambient hooks, instructions, plugins, skills, MCP, profiles, or history;
- generate and validate the mandatory custom permission profile; do not mix it with legacy `--sandbox`;
- use an empty `/runtime/author-cwd`, `/workspace` only through `--add-dir`, explicit `-a never`, `--strict-config`, `--skip-git-repo-check`, disabled web search, and the same boundary on exact-ID resume;
- capture `thread_id` from `thread.started`, never use `--last`, and parse bounded JSONL events without trusting final prose;
- capability-probe exact flag placement, permission effects, credential refresh, and first/resume behavior on the pinned version;
- use `codex debug prompt-input` and hostile-marker smoke tests to prove root `AGENTS.md`, `AGENTS.override.md`, and `.codex/**` in the additional subject directory never become control instructions. Reject affected repositories/versions rather than deleting subject files.

For Claude:

- require the operator-selected dedicated `claude setup-token` credential; never read the ambient keychain;
- launch from an empty private cwd with safe mode, no session persistence, `dontAsk`, an empty built-in tool list, denied MCP tools, two max turns, JSON output, and the exact versioned JSON Schema;
- use the environment scrubbing, API timeout/retry, and one structured-output-retry limits from `PLAN.md`;
- pass only the complete sanitized bounded bundle on stdin;
- retain the full envelope privately, classify process/error/retry/max-turn failures before parsing, extract only top-level `structured_output`, then independently validate schema and semantics locally;
- keep every Claude round fresh and tool-disabled.

Real paid smoke tests require explicit operator confirmation after printing the exact models, credential identifiers—not secret values—estimated scope, timeouts, and round limit. A parser/probe failure is a failed gate, not permission to guess or add compatibility fallbacks.

#### Phase 5 — Serial loop and usability

Join only already-proven components into:

- `agent-loop run` with the exact task/check/limit/protected-path behavior and conservative defaults in `PLAN.md`;
- `agent-loop status <run-id>`;
- `agent-loop show <run-id> [--round N]`;
- strict `.agent-loop.toml` project configuration that cannot broaden frozen boundaries silently;
- interactive preflight confirmation, with `--yes` only for deliberate scripting;
- fresh critic rounds, exact Codex thread resume during a healthy run, deterministic fatal/success/cap/stall ordering, complete artifact retention, and Ctrl-C cleanup;
- a `pipx`-installable package and operator documentation.

Do not implement interrupted-run continuation. Preserve evidence after interruption and stop.

## Security-focused coding rules

- Prefer typed immutable domain objects and total parsing functions at every trust boundary.
- Keep raw bytes until an explicitly encoded display or model boundary; never assume Git paths are UTF-8.
- Never concatenate untrusted values into host shell commands. Trusted runner commands use argv arrays. User-provided validation command strings execute only inside the validation sandbox under the frozen policy.
- Start subprocesses with an allowlisted environment, close inherited descriptors, bound stdout/stderr while streaming, and use monotonic deadlines.
- Treat subprocess exit status, timeout, signal, stream truncation, cleanup state, protocol validity, and deadline eligibility as separate facts.
- Use explicit schema versions, reject unknown properties, cap every collection and free-text field, and normalize only fields named by the specification.
- Do not forward raw validation output, raw critic prose, or source-embedded instructions between agents.
- Do not log secrets even at debug level. Test logs and exception messages for accidental credential content.
- Make cleanup idempotent, but never let cleanup errors erase the original fatal state or turn a failure into success.
- Prefer fail-closed typed errors with the stable public category and a precise private `stop_reason`.
- Use dependency injection for clocks, process launchers, services, credentials, filesystems, Git, and agent transports so failure paths can be tested deterministically.
- Use property-based/fuzz testing for manifest canonicalization, arbitrary paths, schema/parser boundaries, size limits, and state-machine invariants where practical.
- No test may require real secrets. Real-CLI tests must be separately marked and opt-in.

## Validation and acceptance discipline

Implement every numbered acceptance test in `PLAN.md`; do not collapse materially different threat cases into one superficial test. Give tests descriptive names that include the plan number, for example `test_015_fatal_integrity_beats_lgtm`.

Maintain these layers:

1. pure unit tests for canonicalization, policies, schemas, state transitions, limits, and error mappings;
2. filesystem/adversarial tests for paths, links, races, metadata, permissions, and atomicity;
3. fake-process integration tests for services, protocols, credentials, timeouts, cleanup, and the complete loop;
4. target-host containment tests for Bubblewrap/systemd/Git behavior;
5. opt-in pinned real-CLI smoke tests, executed last.

For each phase:

- run the narrow tests while iterating;
- run formatting, linting, strict type checks, unit, integration, and adversarial suites before declaring the phase complete;
- record exact commands and results in `docs/IMPLEMENTATION_STATUS.md`;
- inspect the diff for accidental broadening, secret leakage, unsafe subprocess use, and unbounded input/output;
- do not advance if a security-boundary test fails.

Tests that cannot run because the current host is not the pinned target must be clearly marked as externally blocked, not skipped-successfully. Provide the exact target-host command and expected assertion. Everything that can be tested with pure code or fakes must still be completed.

## Definition of done

Version 1 is complete only when:

- the package installs in a clean environment and exposes the three specified commands;
- phases 1 through 5 are implemented without adding a deferred feature or alternate boundary;
- all applicable automated checks pass and all 72 plan acceptance tests have explicit executable coverage;
- target-only tests pass on the pinned Ubuntu/Bubblewrap/systemd/CLI matrix, or the final report clearly states that implementation is not complete because those external gates remain blocked;
- fake-agent end-to-end tests demonstrate happy path, revision path, every termination category, credential recovery, evidence withholding, hostile return data, and cgroup cleanup;
- real-CLI smoke tests, if explicitly authorized, prove exact Codex first/resume and fresh Claude critic behavior without leaking credentials;
- no TODO, placeholder, permissive fallback, broad exception swallowing, or mock remains in a version-1 production path;
- documentation explains setup, limits, security assumptions, sensitive artifact handling, credential rotation/recovery, and project configuration;
- the final Git diff contains only intentional implementation and documentation changes and leaves `PLAN.md` unchanged.

## Communication and final handoff

Lead progress updates with completed outcomes and current blockers. Do not flood the operator with command logs, but preserve full evidence in the repository's test output/status artifacts where appropriate.

At completion, report:

1. what was implemented by phase;
2. the important files and architecture boundaries;
3. every check run and its result;
4. the acceptance-test coverage count and any genuinely blocked target-host tests;
5. security limitations that remain exactly as acknowledged by `PLAN.md`;
6. any operator actions still required, especially credential provisioning or explicitly authorized paid smoke tests;
7. confirmation that `PLAN.md` was not modified and that no commit, push, PR, package publication, or remote mutation occurred.

Begin now by reading `PLAN.md` in full, inspecting the worktree and environment, creating the traceability matrix, and implementing Phase 1. Continue autonomously through every safe, unblocked phase.

---

This execution prompt follows the Codex prompting pattern of an explicit goal, relevant context, hard constraints, and a verifiable definition of done. The frozen plan remains authoritative.
