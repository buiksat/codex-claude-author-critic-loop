# Codex implementation prompt for `plan-v1.1`

**Status:** Fulfilled and target-host qualified on 2026-07-21. Retained as the historical execution contract; it is not an open implementation request.

The prompt below was executed from the repository root. It is not a replacement for [`PLAN.md`](PLAN.md). `PLAN.md` is the qualified but still-unfrozen successor specification pending formal change control and wins if this companion prompt is incomplete or ambiguous. The historical `plan-v1.0` tag remains immutable.

---

You are the lead implementation engineer for this repository. Implement the `plan-v1.1` successor specification in `PLAN.md` as a production-quality, security-sensitive Python application.

## Mission

Deliver a working `agent-loop` CLI that runs a bounded Codex-author / Claude-critic coding loop exactly as specified by `plan-v1.1`.

Do not merely analyze the plan, produce another plan, or stop after scaffolding. Work through the implementation phases in order, write the code and tests, run the applicable checks, diagnose failures, and continue until the version-1 completion criteria are met or a genuine external prerequisite makes further progress impossible.

The intended outcome is a containment-first local execution runtime with an agent loop on top. Treat it accordingly; this is not a small shell wrapper.

## Source of truth and precedence

1. Read `PLAN.md` completely before editing anything.
2. Treat its successor contracts, security boundaries, state machine, exit codes, pinned platform matrix, evidence adapters, live-receipt lifecycle, phases, and all 78 acceptance tests as normative.
3. Treat this prompt as execution guidance only. If it conflicts with `PLAN.md`, follow `PLAN.md` and record the discrepancy.
4. Do not edit `PLAN.md` while executing this prompt. A further required normative change is not an implementation detail: stop that affected path, explain the conflict precisely, and propose the next successor without weakening `plan-v1.1`.
5. Preserve existing user changes. Inspect Git status and diffs before editing; never overwrite unrelated work.
6. Use only official OpenAI, Anthropic, Git, Linux, Bubblewrap, systemd, Python, and Ubuntu documentation when exact behavior needs verification. The pinned CLI behavior and successful local capability probes recorded in `PLAN.md` take precedence for this version.

## Operating authority and prohibitions

You are authorized to create and edit project files, run local formatting/static-analysis/unit tests, and run non-destructive containment probes needed to implement the repository.

You are not authorized to:

- weaken, bypass, stub out, or silently downgrade a security contract so a test passes;
- edit the successor plan while implementing it;
- commit, reset, clean, push, open or merge a PR, publish a package, or otherwise mutate a remote;
- use `danger-full-access`, `--dangerously-bypass-approvals-and-sandbox`, an unbounded shell loop, or an alternate unreviewed sandbox backend;
- fetch packages or run installers without first reporting the exact missing dependency and using the repository's declared, reviewable dependency workflow;
- expose, print, copy into artifacts, or pass to model-generated commands any credential, token, keychain state, cloud configuration, socket, or ambient user configuration;
- make paid/live Codex or Claude model calls until the fake-agent and containment gates pass, the one-time default credential profile is valid, and the operator explicitly accepts the printed live-smoke scope/cost gate; do not ask for secret values or repeat credential identifiers per run;
- claim a check passed when it was skipped, simulated, or blocked by the host environment.

Use reasonable implementation judgment inside the successor interfaces. Do not pause for routine choices that can be made safely and reversibly. Ask the operator only when a required project-specific input is absent or an action needs authority beyond the scope above.

## Required working method

### 1. Orient and establish traceability

Before implementation:

- inspect the repository, Git status, current platform, kernel, Python, Git, Bubblewrap package/mode, fixed root-owned author-manager install/authorization state, systemd user-service availability, Codex version, and Claude version;
- compare the environment with the pinned matrix without changing the host;
- read every section of `PLAN.md`, including the historical review dispositions, limitations, and acceptance tests;
- create `docs/IMPLEMENTATION_STATUS.md` containing:
  - the detected environment and compatibility result;
  - a phase checklist matching phases 1 through 5;
  - a table mapping acceptance tests 1 through 78 to test names/files and status (`pending`, `passed`, `blocked`, never `assumed`);
  - decisions made within non-normative implementation freedom;
  - external prerequisites and exact reproduction commands for any block.

Keep that status document current as work proceeds. It is evidence, not a substitute for executable tests.

### 2. Establish a maintainable Python project

Create a conventional `src`-layout, `pipx`-installable unprivileged Python package with an `agent-loop` console entry point, plus the reviewed failure-atomic bootstrap that installs the version-matched fixed root-owned author manager/unit/socket/policy/supervisor from an exact hash-verified wheel and authorizes one numeric UID. Prefer a minimal dependency set and standard-library primitives where they are adequate. Pin supported versions and hashes through the project's chosen reproducible dependency mechanism. The CLI must never invoke the bootstrap from `run`, and the privileged closure must never execute from a mutable checkout or user-writable virtualenv. A signed distro-native Debian package is explicitly deferred.

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
├── service.py               # fixed author-manager and user-service lifecycle/cgroup checks
├── host_manager.py          # closed root-manager protocol and one-time install contract
├── sandbox.py               # privileged outer/user Bubblewrap policies and supervisor protocol
├── sandbox_init.py          # in-namespace materialize/run/kill/scan/export
├── validation.py            # baseline/current checks and mutation detection
├── declassify.py            # raw-log separation and critic-safe evidence
├── credentials.py           # locked Codex/Claude file transactions and fallback adapters
├── schemas.py               # Claude wire schema plus authoritative local semantic checks
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
- deterministic root-owned bootstrap/install metadata, packaged unit/socket/policy assets, version/protocol handshake data, and failure/repair/reinstall tests that do not grant arbitrary system-manager authority;
- a concise `README.md` covering purpose, pinned support matrix, installation, automatic reuse of existing vendor CLI sign-ins, exceptional credential recovery, basic commands, security warnings, and development checks;
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

Implement the two fixed execution families and no fallback:

- the administrator-installed, root-owned `agent-loop-author-manager.service`, Unix socket, fixed job contract, immutable policy/install closure, root-owned allowlist for the exact reviewed Codex installation digest, and trusted supervisor for author turns;
- a closed, versioned, bounded Unix-socket protocol authenticated with `SO_PEERCRED`; requests may contain only the exact capped SCM_RIGHTS descriptor classes and canonical sandbox payload in `PLAN.md`; independently reject every non-pinned executable/argv/environment/cwd/limit shape, host source pathname, identity, capability, shell, arbitrary mount destination, or systemd property;
- descriptor verification for peer ownership where applicable, type, mode, access direction, seals/no-follow provenance, size/count, uniqueness, and immutable role-to-destination mapping; independently snapshot and hash each admitted read-only closure, require the Codex digest to match the root-installed allowlist, and require the Python-source digest to match the installed wheel runtime closure rather than trusting caller-supplied witnesses;
- no unprivileged permission to call system-manager `StartTransientUnit`, start arbitrary units, broaden the fixed user-level Codex command/mount grammar, or obtain a root shell; install/update/uninstall is a separate explicit administrator action from a reviewed root-owned, hash-verified wheel copy and root-owned installer, never service assets read from a mutable source tree or user-writable virtualenv;
- a privileged outer author mount/PID/IPC/UTS namespace and sized full tmpfs, followed by permanent drop to the authorized UID/GID with empty supplementary groups, zero capabilities, `no_new_privs`, and reviewed seccomp/LSM policy before Codex starts;
- preservation of Ubuntu's standard Bubblewrap AppArmor restriction while leaving exactly one unprivileged namespace transition for Codex's mandatory inner permission-profile Bubblewrap; never weaken AppArmor, use `danger-full-access`, or remove the inner profile;
- patched non-setuid Ubuntu Bubblewrap plus fixed user-service launchers for validation, hardened Git, and Claude; these paths do not nest a Codex sandbox;
- a trusted `sandbox-init` as the namespace supervisor, a fresh explicitly sized full tmpfs workspace rather than an overlay, pre-opened bounded manifest/blob input and export channels, and materialize → launch → wait → kill all descendants → prove empty → complete scan/export → exit;
- exact service properties from `PLAN.md`, including `Type=exec`, `KillMode=control-group`, `SendSIGKILL=yes`, bounded `TimeoutStopSec`, `OOMPolicy=kill`, `CollectMode=inactive-or-failed`, memory/task/runtime/file-size/file-descriptor/core limits;
- process-group handling only as supplemental cleanup, never as the containment boundary;
- no network for model-generated commands, validation, Git, or critic tools; normal host egress only for trusted Codex and Claude control binaries;
- no host home, credentials, sockets, artifact tree, control state, mutable caches, or unreviewed toolchain mounts in untrusted execution paths;
- denial of `/proc` environment/fd/memory inspection, ptrace, `process_vm_readv`, `pidfd_getfd`, core dumps, and inherited-descriptor leakage;
- stable procfs topology attestation that parses `NSpid` as an outer-to-inner vector of positive ASCII decimal PIDs, uses its rightmost component as the namespace-local PID, resolves `PPid` through the outer-label-to-local-PID map, and requires unchanged numeric `/proc` listings around the complete status scan. Retry disappearance or listing drift by restarting the whole scan at most three times; reject malformed/missing vectors, duplicate local PIDs, other read errors, or persistent churn;
- byte/file/output/deadline bounds and cgroup emptiness verification on success, failure, timeout, OOM, interrupt, fork, daemonization, and new sessions.

The Bubblewrap package probe must check the Ubuntu package revision, upstream version, owner, mode, setuid bit, and binary hash as specified. The author-manager probe must verify its complete root-owned executable/unit/socket/config/policy/supervisor/installer closure, authorized numeric UID, closed protocol, direct systemd-manager denial, permanent privilege drop, and real inner-Codex-sandbox composition. Do not claim a hard inode quota. If the host cannot prove either required family, preserve completed portable/pure code but report integration as blocked; do not substitute Docker, `codex sandbox`, an overlay, arbitrary transient-unit authorization, AppArmor weakening, or a weaker process wrapper.

Implement pristine-base and post-candidate validation using the full-tmpfs supervisor protocol on the user-service backend. Validation must operate on a separately materialized frozen subject, retain a bounded sensitive raw log locally, export a mutation manifest, and never modify the authoritative subject.

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
- per-source/run locking and globally ordered account-scoped credential locking;
- absent-default lazy bootstrap from the authorized UID's passwd-home `.codex/auth.json` and `.claude/.credentials.json` paths, never inherited `HOME`/`CODEX_HOME`/`CLAUDE_CONFIG_DIR`; optional advanced `auth init/status/reauthenticate`; a non-secret hashed default-pair commit; and copy/validate/fsync/atomic-promote/pair-transition-crash-recovery transactions without logging secret bytes. A private profile-level transition journal must bind both transaction IDs and old/new pair hashes before the first durable promotion, roll old/mixed/new crash states forward under profile → Claude → Codex locks, fail closed on missing/ambiguous witnesses, and be removed last after pair metadata and cleanup. Lazy bootstrap must occur before spending, use confined parent/file owner/mode/type/single-link/size/syntax checks and exclusive creation under the same lock order, unconditionally remove both new stores and metadata after ordinary failure, and detect/fail closed on hard-crash partial state. For an existing valid default pair, inspect only the exact standard paths under the same locks; accept only a strictly newer pinned generation, probe it in a disposable private home before staging, preserve input/post-probe generations at the evidence barrier, and atomically commit accepted one/two-provider changes through the pair journal. Equal, older, invalid, unsafe, custom-profile, interrupted, or failed local-probe sources must never replace durable state. Treat local status success as local CLI acceptance, not proof against remote revocation. Normal vendor login recovery is vendor login once followed by rerunning the original command, with no `agent-loop auth` import step;
- default per-vendor transaction entry points reject standalone acquisition; ordinary runs and both paid live probes must use the combined profile transaction so every validated Codex-only, Claude-only, or dual refresh updates the paired commit witness;
- normal Claude account-file authentication under private `CLAUDE_CONFIG_DIR` and `HOME=/nonexistent`, with no ambient keychain/config or normal-path token/API-key environment state; setup-token/API-key profiles are explicit separately qualified fallbacks only;
- the honest managed-Claude trust boundary: the exact reviewed/receipt-bound managed closure shares the credential-bearing control namespace and can technically read `.credentials.json`; scrub credential environment variables, forbid unreviewed managed executables/children and all model tools, and test closure/process-set drift rather than claiming impossible same-UID file denial;
- baseline/current validation classification and protected-harness behavior;
- raw validation logs versus separately declassified, approval-eligible structured evidence;
- semantic-delta completeness, bundle byte/token/file/field budgets, and fail-closed withheld-content/evidence handling;
- the exact canonical remote-compatible Draft-07 critic wire schema: a closed plain-object root with one required `review` property whose value uses the nested `anyOf` LGTM/REVISE/BLOCKED discriminator, no root combinator or `if`/`then`, exact `structured_output.review` extraction, independent authoritative local schema/semantic validation, and normalized return-path prompts;
- hostile source/log/review text treated exclusively as delimited data.

Never grep prose for approval. Only a locally revalidated `structured_output.review` object, extracted from the exact closed `structured_output` wrapper, can supply `LGTM`, and it is semantically valid only when every success predicate in `PLAN.md` is true.

#### Phase 4 — Pinned real-CLI integration

Only after phases 1 through 3 pass, add adapters for the pinned CLIs.

For Codex:

- route every author turn through only the fixed root-owned author manager and exact descriptor protocol; prove unauthorized/malformed requests and direct system-manager operations fail, outer privilege is permanently dropped, and the real inner Codex Bubblewrap profile works under unchanged host AppArmor policy;
- build the sanitized account-transaction `CODEX_HOME` exactly as specified, importing no ambient hooks, instructions, plugins, skills, MCP, profiles, or history; explicitly disable every pinned vendor system skill and app/plugin/goal/personality/collaboration control-context surface, then prove the effective prompt/tool set is clean;
- generate and validate the mandatory custom permission profile; do not mix it with legacy `--sandbox`;
- use an empty `/runtime/author-cwd`, `/workspace` only through `--add-dir`, explicit `-a never`, `--strict-config`, `--skip-git-repo-check`, disabled web search, and the same boundary on exact-ID resume;
- capture `thread_id` from `thread.started`, never use `--last`, and parse bounded JSONL events without trusting final prose;
- when public events omit model/effort facts, apply only the exact descriptor-confined pinned-rollout parser and qualified client-evidence semantics in `PLAN.md`; reject reroutes, drift, ambiguity, lifecycle mismatch, and resume prefix mismatch;
- capability-probe exact flag placement, permission effects, credential refresh, and first/resume behavior on the pinned version;
- use `codex debug prompt-input` and hostile-marker smoke tests to prove root `AGENTS.md`, `AGENTS.override.md`, and `.codex/**` in the additional subject directory never become control instructions. Reject affected repositories/versions rather than deleting subject files.

For Claude:

- use the default account-scoped transactional `.credentials.json` initially imported and later strictly-monotonically synchronized from the standard Claude login; point `CLAUDE_CONFIG_DIR` at only that transaction, set `HOME=/nonexistent`, reconcile valid refreshes atomically, and never read ambient keychain/config or inject a normal-path token/API key;
- keep setup-token/API-key profiles as explicit typed, separately qualified fallbacks only; never auto-fallback after account-file failure;
- inspect and bind the exact managed-policy executable/config closure and observed child set. Treat it as trusted credential-bearing control code with control egress and possible transaction-file access; environment scrubbing is defense in depth, not file isolation. Reject any unreviewed managed executable/child before spending. For pinned Claude 2.1.215, accept only the full contiguous attestation `AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:reviewed-managed-boundary-v1:credential_absent:scrub=1` or the one exact vendor-redacted alternative `AGENT_LOOP_MANAGED_CLAUDE_BOUNDARY_OK:reviewed-managed-boundary-v1:credential_absent:[REDACTED]`; reject partial markers, case variants, different substitutions, and freely placed redaction tokens;
- launch from an empty private cwd with safe mode, no session persistence, `dontAsk`, an empty built-in tool list, denied MCP tools, two max turns, JSON output, and the exact canonical remote-compatible Draft-07 plain-root/nested-`anyOf` review-wrapper schema with no root combinator or `if`/`then`;
- use the environment scrubbing, API timeout/retry, and one structured-output-retry limits from `PLAN.md`;
- enable only the pinned API debug category and parse its exact bounded request-selection diagnostic as client evidence; prove the API retry ceiling against a loopback-only deterministic endpoint;
- pass only the complete sanitized bounded bundle on stdin;
- retain the full envelope privately, classify process/error/retry/max-turn failures before parsing, extract only the exact top-level `structured_output.review` wrapper, revalidate the wire shape, then independently enforce every stricter local size/range/verdict/cross-field/validation-state semantic rule;
- run the authorized paid compatibility probe that proves the exact plain-root/nested-`anyOf` wire schema reaches pinned Claude 2.1.215 without a pre-inference HTTP `400`, matches the diagnostic request schema, returns the closed wrapper at top-level `structured_output`, and places the review only at `structured_output.review`; separately prove rejection of a root combinator, an unwrapped review, unknown wrapper properties, and wire-valid local contradictions without guessing or undeclared retry;
- keep every Claude round fresh and tool-disabled.

Real paid smoke tests require the existing single explicit operator confirmation (`--accept-paid` or its interactive equivalent) after printing the exact models, default non-secret credential-profile/account identifiers—not secret values—estimated scope, timeouts, and round limit. This is a start/cost gate, not another login. A parser/probe failure is a failed gate, not permission to guess or add compatibility fallbacks.

Treat the schema-v3 `live-v3.json` receipt as a narrowly bound authorization cache, never as general conformance evidence. Only the installed `agent-loop qualify --live --accept-paid` command may mint or refresh it, and only after one clean in-process run of every required host/live gate. Pytest is diagnostic only and has no production receipt-issuance authority. The receipt must bind every dimension and expire as specified, and it must be rejected before spending on any mismatch or older schema.

#### Phase 5 — Serial loop and usability

Join only already-proven components into:

- `agent-loop run` with the exact task/check/limit/protected-path behavior and conservative defaults in `PLAN.md`;
- `agent-loop status <run-id>`;
- `agent-loop show <run-id> [--round N]`;
- absent-default lazy auth bootstrap during ordinary preflight, locked strictly-newer standard-login adoption on later runs, plus optional `agent-loop auth init/status/reauthenticate` for explicit identities/paths, reviewed integrity repair, and separately qualified fallback adapters; include default-profile selection, local-only status labeling, one-vendor-login-and-rerun failures, and no raw secret argv;
- `agent-loop qualify --live` with the single explicit paid-scope gate and schema-v3 receipt lifecycle;
- `agent-loop run --dry-run` for a no-spend resolved preview;
- strict `.agent-loop.toml` project configuration that cannot broaden frozen boundaries silently;
- one consolidated interactive start/cost confirmation, with `--yes` only for deliberate scripting; never add a per-run sudo/Polkit, browser, token, secret-environment, or credential-identifier prompt;
- fresh critic rounds, exact Codex thread resume during a healthy run, deterministic fatal/success/cap/stall ordering, complete artifact retention, and Ctrl-C cleanup;
- a `pipx`-installable unprivileged package, a version-matched reviewed hash-verified wheel bootstrap for the root-owned service, and operator documentation separating the one-time administrator bootstrap/UID authorization, first-run lazy reuse of active standard CLI file logins, automatic post-login adoption, optional advanced integrity repair/fallback setup, live qualification, and ordinary runs.

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

- the unprivileged package installs in a clean environment and exposes every CLI command specified by the current plan; the version-matched reviewed bootstrap installs only the fixed root-owned manager closure with exact ownership/modes, one authorized numeric UID, rollback on failure, and no user-writable execution path;
- phases 1 through 5 are implemented without adding a deferred feature or alternate boundary;
- all applicable automated checks pass and all 78 plan acceptance tests have explicit executable coverage;
- target-only tests pass on the pinned Ubuntu/Bubblewrap/systemd/CLI matrix, or the final report clearly states that implementation is not complete because those external gates remain blocked;
- fake-agent end-to-end tests demonstrate happy path, revision path, every termination category, credential recovery, evidence withholding, hostile return data, and cgroup cleanup;
- real-CLI smoke tests, if explicitly authorized, prove fixed-manager/inner-Codex first/resume composition, fresh Claude account-file critic behavior, and remote plain-root/nested-`anyOf` review-wrapper compatibility without leaking credentials;
- no TODO, placeholder, permissive fallback, broad exception swallowing, or mock remains in a version-1 production path;
- documentation explains one-time administrator installation, absent-default exclusive bootstrap, strictly-newer standard-login adoption and rollback bounds, optional advanced integrity repair/fallback setup, ordinary no-reauth runs, the distinct start/cost gate, limits, security assumptions, sensitive artifact handling, credential rotation/recovery, and project configuration;
- the final Git diff contains only intentional implementation and documentation changes and conforms exactly to the current `PLAN.md` successor.

## Communication and final handoff

Lead progress updates with completed outcomes and current blockers. Do not flood the operator with command logs, but preserve full evidence in the repository's test output/status artifacts where appropriate.

At completion, report:

1. what was implemented by phase;
2. the important files and architecture boundaries;
3. every check run and its result;
4. the acceptance-test coverage count and any genuinely blocked target-host tests;
5. security limitations that remain exactly as acknowledged by `PLAN.md`;
6. any operator actions still required, especially one-time host-package installation/UID authorization, one vendor login independently confirmed necessary by its CLI followed only by rerunning the original command, advanced integrity repair/fallback selection, or the paid-smoke start gate;
7. confirmation that no further unreviewed normative change, commit, push, PR, package publication, or remote mutation occurred.

This execution contract has been fulfilled through Phase 5 and the installed-command target-host qualification. Do not restart it as an open task. Any subsequent implementation change must begin from the still-unfrozen `PLAN.md` and follow its formal change-control policy before the successor is frozen.

---

This fulfilled execution prompt follows the Codex prompting pattern of an explicit goal, relevant context, hard constraints, and a verifiable definition of done. The qualified current successor plan remains authoritative but unfrozen pending formal change control; the immutable `plan-v1.0` tag remains historical evidence.
