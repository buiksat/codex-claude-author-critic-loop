# agent-loop

`agent-loop` is a containment-first implementation of the unfrozen
[`plan-v1.1`](PLAN.md) successor design: Codex is the only code-writing author, Claude is a fresh
tool-disabled critic, and a deterministic Python runner owns validation, limits, evidence, and
stop decisions.

The original `plan-v1.0` tag remains an immutable historical baseline. Qualification exposed an
Ubuntu namespace-composition failure in the author boundary, a remotely unsupported Claude schema
keyword combination, and unnecessary authentication ceremony. `plan-v1.1` addresses those findings
with a fixed administrator-installed author broker, a remote-compatible critic wire schema plus
strict local semantics, and private reuse of already-present Codex and Claude CLI file logins. The
successor implementation is now qualified on the pinned host: repository test evidence is
`814 passed, 8 skipped`, and the exact installed wheel passed the installed qualifier's 18 live
gates and minted a schema-v3 receipt. The root-owned install record and private receipt, rather than
this packaged document, carry the artifact hashes so rebuilding documentation cannot create a
self-referential digest claim. That receipt proves only its exact bound
host, artifact, selections, and 18-gate scope; it is not by itself a `78/78` acceptance claim.
Installation and ordinary deterministic tests make no paid model calls. Do not treat the package as
a production security boundary; see
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) for current evidence.

**Current status: implementation qualified on the pinned host; `plan-v1.1` remains unfrozen pending
repository change control.**

## Pinned qualification matrix

Version 1 deliberately has no compatibility fallback.

| Component | Supported value |
|---|---|
| OS and architecture | Ubuntu 26.04, x86_64 |
| Python | CPython 3.14.4 |
| Git | 2.53.0 |
| Bash | 5.3.x |
| systemd | 259 (`259.5-0ubuntu3` in the pinned probe) |
| Bubblewrap | upstream 0.11.1, Ubuntu `0.11.1-1ubuntu0.1` |
| Bubblewrap binary | `/usr/bin/bwrap`, root-owned, mode `0755`, non-setuid |
| Bubblewrap SHA-256 | `0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0` |
| Codex CLI | 0.144.6 |
| Claude Code | 2.1.215 |

The host must also pass the `openat2`, user-namespace, Bubblewrap, transient user-service, resource,
network, and descendant-cleanup probes. A newer patch, another Linux distribution, Docker, a
setuid Bubblewrap build, or a different sandbox is unsupported until reviewed and capability-tested.

## Install

Use the exact supported Python and an already-provisioned reviewed build dependency to build a
wheel without isolation or network resolution, then install that reviewed artifact:

```bash
python3.14 -c 'import setuptools; assert setuptools.__version__ == "78.1.1"'
PIP_NO_INDEX=1 python3.14 -m pip wheel . --no-cache-dir --no-build-isolation \
  --no-deps --wheel-dir dist
PIP_NO_INDEX=1 pipx install dist/agent_loop-1.1.0-py3-none-any.whl --python python3.14
agent-loop --help
```

For source-tree development without an editable install:

```bash
PYTHONPATH=src python3.14 -m agent_loop.cli --help
```

The build-system requirement is exactly `setuptools==78.1.1`. The runtime package uses the Python
standard library. This repository does not vendor a setuptools wheel or lock its artifact hash, so
the operator must supply that exact build backend through an independently reviewed offline
dependency workflow; these commands do not authorize fetching it. The test suite uses the
host-provided `pytest` and `jsonschema`; do not fetch tooling implicitly on a production runner.

The source distribution retains `PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, `schemas/`, and the
reviewed administrator-boundary sources under `support/`. A wheel installs the same successor
evidence and support sources under `share/agent-loop/` beneath the installation prefix. It does not
modify system paths; administrator-owned assets require a separate, explicit, one-time bootstrap.

## Authentication: existing CLI sign-ins are reused automatically

If Codex CLI and Claude Code are already signed in, run `agent-loop` directly. There is no
`agent-loop auth` setup step, credential profile prompt, token paste, or per-project login. Sign in
to a vendor only when its own status command reports that it is signed out, or when an actual model
request returns the runner's exact vendor-session-ended diagnostic. Then rerun the original
command:

```bash
codex login          # after confirmed sign-out or an exact remote-session rejection
claude auth login    # after confirmed sign-out or an exact remote-session rejection
```

On the first run, `agent-loop` privately copies the supported standard file-backed sessions from
the authorized operator's passwd-resolved home (not an inherited model-controlled `HOME`) at these
locations:

```text
~/.codex/auth.json
~/.claude/.credentials.json
```

It copies neither surrounding CLI configuration nor the user's home. Later runs reuse the private
default pair and persist valid vendor refreshes automatically. If a vendor later signs you out,
run only that vendor's normal login command once and rerun the failed `agent-loop` command. A
strictly newer standard login is detected, probed in disposable private state, and atomically
adopted under the same
locks; no `agent-loop auth init`, import, or repair step is required. Stale or equal ambient files
can never roll the private pair backward.

Behind the scenes, that initial private copy verifies ownership, modes, file types, credential
shape, and pinned CLI compatibility. Private stores are mode `0700`, credential files are mode
`0600`, and updates
use a locked, fsynced two-provider transaction so a crash cannot silently leave a half-updated
pair. Only a valid pair may synchronize strictly newer standard generations. Invalid, partial, or
ambiguous managed state is never overwritten automatically; that exceptional case stops before
spending and gives an advanced integrity-repair command.

Credential state remains outside retained runs:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/agent-loop/credentials/
├── default-profile.json
├── default-profile-transition.json  # present only during recoverable pair commit
├── lock
├── codex/default/
│   ├── auth.json
│   ├── lock
│   └── transactions/<run-id>/
└── claude/default/
    ├── credentials.json
    ├── lock
    └── transactions/<run-id>/
```

### Advanced authentication diagnostics and recovery

Most users should never run these commands. `agent-loop auth status` is a local, secret-free
diagnostic. Use `auth init --repair` only when the runner explicitly reports
`repair_required`; ordinary sign-in, sign-out, refresh, and rotation do not need it:

```bash
agent-loop auth status
agent-loop auth init --repair           # only after an explicit repair_required result
```

Custom credential IDs and nonstandard import paths remain available through
`agent-loop auth init --help` for advanced deployments.

`agent-loop auth status` reports both per-vendor
`local_copy_present_and_parseable` values, explicitly reports vendor session validity as
`not_checked`, and includes a secret-free
`default_profile.state`: `absent`, `ready`, `busy`, `recovery_pending`, or `repair_required`. It
uses a short lock wait, so an active run reports `busy` instead of hanging. A pending valid paired
transition is recovered automatically by the next intended run. A partial or ambiguous first
bootstrap fails closed as `repair_required`. Only that state names `agent-loop auth init --repair`,
including for stores created before the paired commit format was introduced.

If a supported file login is genuinely unavailable, the run stops before spending and names the
vendor status/login command. The local status probe is not a remote-validity proof: an actual model
request can still identify a remotely rejected Codex or Claude session and return the exact
vendor-specific one-login-and-rerun diagnostic. Reauthenticate directly after that exact remote
diagnostic even if the status command still reports a local login. A generic probe or process
failure alone does not prove expiry or revocation, so check the vendor status command first in that
case. A local runner cannot remove the vendors' account boundary, but it removes redundant
project-specific and per-run authentication. Keyring-only, setup-token, and API-key profiles
require a separately qualified advanced adapter and never activate implicitly.

## One-time administrator boundaries

The pinned Codex CLI launches model-generated commands through its own Bubblewrap permission
profile. On the target Ubuntu host that inner sandbox cannot be nested beneath the former
unprivileged outer Bubblewrap namespace. The successor therefore uses one fixed, root-owned,
socket-activated author broker. An administrator reviews a hash-verified built artifact and
authorizes exactly one numeric operator UID and one reviewed Codex installation-closure digest
during installation. The broker independently snapshots and hashes the supplied runtime and Codex
closures on every request, accepting only the installed wheel runtime and the root-owned Codex
allowlist. It has a fixed protocol, command, mount set, limits, and systemd policy; an ordinary user
cannot supply arbitrary argv, unit properties, paths, environment, or substitute executable.

The reviewed, failure-atomic bootstrap and exact digest-bound replacement procedure are packaged
under [`support/author-service/`](support/author-service/README.md). This is a one-time host
operation, not an authentication step: after it succeeds, ordinary `agent-loop run` commands
connect through the protected Unix socket and require no `sudo`, Polkit, or administrator prompt.

### Managed Claude boundary

The reviewed assets under `support/managed-claude-boundary/` define the only managed Claude policy
accepted by production: an exact `/etc/claude-code/managed-settings.json` and a small fixed
SessionStart attestation helper at
`/usr/local/libexec/agent-loop-claude-boundary-attest`. Review those sources, then perform the
non-privileged dry check from the repository root:

```bash
bash support/managed-claude-boundary/install.sh --check
```

The check statically compiles the helper and exercises its accepted input, fixed marker, and
credential-rejection behavior. It does not invoke `sudo`, modify system paths, inspect a credential
store, or call either model. Once that succeeds, the explicit administrator installation is:

```bash
bash support/managed-claude-boundary/install.sh
```

The installer requests privilege through `sudo`; do not invoke the whole script as `sudo bash`. It
refuses any existing `/etc/claude-code` path or helper target rather than replacing it. It verifies
and reuses a safe root-owned mode-`0755` `/usr/local/libexec`, creating only that final directory if
it is absent; it never chmods or chowns an existing shared directory. On a new installation it
creates the mode-`0755` policy directory, installs the helper mode `0555` and the policy mode `0444`,
and finishes by running the production boundary inspector over their exact metadata, content, and
closure hashes. An existing Claude system policy must be reviewed and reconciled by an
administrator; this script never deletes or silently replaces it.

These commands provision only the non-secret managed boundary. They do not import or expose either
CLI credential and do not authorize spending. Paid qualification is authorized later, explicitly,
with `agent-loop qualify --live --accept-paid`; no paid-confirmation environment variables are
needed for installed use.

## Configuration and commands

The normal command interface is intentionally short; `--state-home` is optional and defaults to
`${XDG_STATE_HOME:-$HOME/.local/state}`:

```bash
agent-loop run \
  --task task.md \
  --check '/usr/bin/python3.14 -m pytest -q'
agent-loop status <run-id>
agent-loop show <run-id> [--round N]
```

With no selection flags, the runner discovers only the exact pinned Codex 0.144.6 and Claude Code
2.1.215 installations, and selects the reviewed receipt-bound defaults: `gpt-5.4`/`high` for the
author and `claude-opus-4-6`/`medium` for the critic. Exact executable/model/effort overrides remain
available for reviewed successor configurations, but any difference intentionally invalidates an
old receipt. The default credential profile is also selected without a flag and, when wholly
absent, is bootstrapped with exclusive, ordinary-exception-atomic writes from the active CLI file
logins before the first model call. A hard-crash partial is detected and fails closed for reviewed
integrity repair rather than becoming usable. The command becomes eligible for production only
after the matching live-capability receipt described below exists.

Add `--dry-run` to the `run` command for a static preview. It resolves and verifies the task,
configuration, committed `HEAD`, exact executable selections, and pinned host boundary, then exits
without discovering/importing credentials, checking or minting a live receipt, running validation,
creating a retained run, or calling either model. A dry run is therefore useful before login or
qualification; it is a preview, not evidence that the paid path is qualified.

`status` reports bounded run state. `show` reports the retained run manifest and structured round
summaries; raw sensitive logs remain separate. A successful run's supported final code handoff is
the normalized private tree at `<run-root>/subjects/current/`, where `<run-root>` is printed by
`run`. Copy that tree to a new destination while no process is operating on the retained run;
files intentionally retain private owner-only modes, and the original source checkout is never
modified automatically. There is intentionally no run-level `resume` command. Exact Codex thread
resume occurs only inside one healthy in-process run.

Project configuration is strict TOML in `.agent-loop.toml` (or `--config PATH`). Unknown keys are
rejected, configured limits may only tighten defaults, protected paths are additive, and validation
commands come only from the operator or this reviewed file:

```toml
schema_version = 1
checks = ["python3.14 -m pytest -q"]

protected_paths = ["scripts/ci/**"]
protected_opt_in_paths = []
discard_only_paths = ["build/**", ".cache/**"]
opaque_nonsemantic_paths = []
review_context_paths = ["pyproject.toml"]
read_only_toolchain_mounts = []

max_rounds = 3
max_runtime_seconds = 2700
author_timeout_seconds = 900
critic_timeout_seconds = 600
validation_timeout_seconds = 600

[limits]
max_files = 20000
max_file_bytes = 4194304
max_total_subject_bytes = 268435456
```

CLI options also cover protected validation harnesses, discard-only and opaque non-semantic paths,
review context, reviewed read-only toolchain paths, exact model/effort values, and timeouts. Model,
effort, and credential-profile overrides are advanced options; omit them for the reviewed defaults
and automatic login reuse. Run `agent-loop run --help` for the concrete spelling.

`protected_opt_in_paths` may contain only exact relative paths declared before the run; globbing and
every `.git` control path are rejected. Because the generated profile cannot express an allow-hole
inside a denied ancestor, an opt-in may remove an ancestor deny from that prevention layer. The
canonical `PathPolicy` remains the exact final authority: only the declared path is opted in,
siblings remain protected, and every `.git` control path remains forbidden. The resulting file
remains in the canonical subject and its change remains semantic.

`opaque_nonsemantic_paths` are also pre-run declarations. A nonempty declaration records an explicit
operator assertion in both the confirmation and durable run evidence. The runner independently
validates that assertion by comparing authoritative validation with a counterfactual subject: an
existing opaque baseline is tested without those entries, and each opaque candidate delta is tested
with the prior opaque entries restored. The complete check behavior and bounded raw evidence must
match exactly. Any difference stops with `review_content_withheld` before Claude; only then may an
opaque delta be omitted from the review bundle. Ordinary additive `protected_paths`,
`--protected-validation-path`, discard-only paths, and review-context paths remain supported.

Before any model call, the version-1 workflow must print the source revision, excluded checkout
changes, baseline, fixed checks, protected/opaque paths, permission boundary, credential adapter
identifiers (never secret values), exact models, and stop conditions. It then requires interactive
confirmation. `--yes` suppresses that prompt only for deliberate automation; it does not relax a
preflight, containment, credential, or spending gate.

### Opt-in real-CLI capability receipt

Production runs require a fresh private schema-v3 receipt proving every receipt-bound target-host
and paid/live gate for the exact host and selections. That receipt is necessary, but is not by
itself proof of all 78 acceptance contracts or completion of deterministic, static-analysis, and
clean-install work listed in the status document. On the pinned target host, after the one-time
administrator boundary installation, the installed command discovers the exact pinned CLIs and
reuses the default private credential pair automatically:

The currently installed wheel passed the installed qualifier's 18 live gates and minted the current
schema-v3 receipt. The root-owned install record and private receipt bind its exact digest. This is
successful qualification evidence for that exact binding, not shorthand for all 78 acceptance
contracts. Use the same generic commands to inspect the paid scope and refresh the receipt when its
bound inputs change or it expires:

```bash
agent-loop qualify --live              # prints the paid scope; makes no model call
agent-loop qualify --live --accept-paid
```

`--accept-paid` authorizes the printed, potentially billable model traffic: one Codex first-turn
call, one exact-resume call, and one Claude CLI review invocation. That Claude invocation may make
one initial model request and, only when its output fails the supplied schema, at most one
schema-correction model request. Its separately configured
`CLAUDE_CODE_MAX_RETRIES=2` API retry budget can retry API attempts and is not the schema-correction
budget. The paid flag is a cost/start gate, not another login or credential selector.

The installed command carries its production probes in the wheel; it does not invoke pytest or
require a repository `tests/` directory. A receipt is written only if acceptance gates
8/9/10/11/29/30/33/49/51/64/65/66/71/72/73/74/76/78 truly pass, including the fixed author-manager
composition, exact observed model/effort evidence, account-auth isolation, and remote Claude wire
schema. The command re-runs the full production preflight and re-hashes the reviewed
broker/config/install closures, exact Codex and Claude install closures, managed Claude boundary,
and location-independent runtime Python-source closure before writing:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/agent-loop/capabilities/live-v3.json
```

The containing directory is mode `0700` and the receipt is mode `0600`. It contains no credential
bytes. It is valid for at most seven days and binds the exact OS/kernel/Python/Git/systemd/Bash and
Bubblewrap facts and probes, executable and install-closure hashes, credential identifiers,
requested models and efforts, the fixed author-manager identity/closure, and the managed Claude
policy/helper absolute paths, closure hashes, attestation protocol, and fixed probe identifier.
Production reconstructs that binding from its current preflight; any mismatch, stale timestamp,
unsafe metadata, or absent receipt stops before spending. Older receipts and partial schema-v3
attempts are neither accepted nor migrated: a successful combined live session is required to mint
or refresh `live-v3.json`.

For Codex 0.144.6, the public success stream is first checked for the pinned server-reroute error
signal. The adapter then confined-reads one exact-thread private rollout, accepts only the pinned
allowlist of durable item types and complete turn lifecycles, and matches the client-resolved
model/effort to the request. Ordinary resume must preserve the prior bytes as a SHA-256-witnessed
prefix plus exactly one turn. Raw rollout contents and the in-memory prefix witness are never copied
into run artifacts.

Installation, documentation, dry runs, and the normal test suite do not run model calls. A local
receipt is evidence for only the exact host and selections it binds; check or refresh it with the
installed `qualify` command after reviewing the printed scope. Any failed or partial qualification
leaves the previous receipt absent or unchanged and never turns into an authentication prompt.

## Default limits

| Boundary | Default |
|---|---:|
| Author rounds / total runtime | 3 / 45 minutes |
| Author / critic / validation timeout | 15 / 10 / 10 minutes |
| Files / one file / total subject | 20,000 / 4 MiB / 256 MiB |
| Path bytes / path depth | 4,096 / 128 |
| Review bundle / estimated input / reserved output | 8 MiB / 64,000 / 8,192 tokens |
| Findings / one free-text field | 128 / 32 KiB |
| Agent output / retained raw validation log | 16 MiB / 32 MiB |
| Workspace tmpfs / service memory | 512 MiB / 1 GiB |
| Tasks / `RLIMIT_FSIZE` / file descriptors | 256 / 64 MiB / 1,024 |

The round, wall-clock, process, stream, tmpfs, memory, task, file-size, descriptor, and export
bounds are independent. Version 1 does not claim a hard inode quota.

## Security and artifact handling

The design requires a private Git-derived subject with no `.git`, ignore-independent manifest
capture, generated transactional Codex and Claude homes, exact thread-ID routing, fresh
tool-disabled Claude reviews, no network for model-generated commands/Git/validation/critic tools,
and one fresh bounded tmpfs for each complete ordered validation suite. Checks in a suite run
sequentially in that shared workspace, with descendants cleaned between checks. Author execution
uses the fixed root-owned outer manager plus Codex's mandatory inner no-network permission-profile
sandbox; validation, Git, and critic containment remain unprivileged user-service boundaries. The
trusted Codex and Claude control processes retain normal host egress for authentication and model
traffic; version 1 does not provide hostname allowlisting.

Runs are retained beneath:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/agent-loop/runs/<run-id>/
```

Directories are mode `0700` and files mode `0600`. Treat the entire run directory as sensitive:
artifacts may contain source, model output, diagnostic patches, and raw validation logs, including
secrets the detector did not recognize. Never publish a run directory wholesale. Credentials are
outside runs and must never appear in prompts, logs, validation mounts, critic bundles, or
artifacts.

Committed-source blobs are staged only in bounded memory until the initial and prepared credential
generations have been checked against configuration, task, source, and pending metadata. Each later
credential generation, including final reconciliation, triggers another generated-configuration
and complete retained-tree scan before the transaction is accepted. Structural fingerprints that
collide with a credential are also withheld from operator output.

If credential bytes collide with retained evidence, or that evidence cannot be classified safely,
the runner deliberately sacrifices the whole run directory rather than preserve questionable
diagnostics. It writes a zero-byte latch in a private control directory outside the run, serializes
that latch with artifact and authoritative-subject operations using a per-run file lock, and erases
the run tree. Reopening retries an interrupted erase and refuses evidence access. Marker persistence
failure is fatal and still triggers best-effort whole-tree erasure; a transient failure is retried
so the durable latch survives recovery. Consequently, run evidence normally survives failures and
interruptions, but is not promised when the credential-evidence barrier activates.

Important limitations remain:

- Permission profiles are beta and require behavioral probes for the pinned Codex version.
- Tool-disabled Claude review is intentionally incomplete and cannot equal repository-wide tooling.
- Repository-controlled checks can be misleading even inside a correct sandbox.
- No network, mutable package cache, host home, Git metadata, submodules, or ambient toolchain state
  means some builds and commands such as `git describe` are unsupported.
- Synthetic homes and a scrubbed `PATH` can break language toolchains unless mounts are reviewed and
  declared before the run; credentialed caches and container sockets remain forbidden.
- `openat2`, Bubblewrap, systemd services, the fixed author broker, and the trusted supervisor are
  Linux security boundaries, not portable conveniences.
- There is no automatic commit, push, PR, publication, direct-checkout mode, linked worktree,
  alternate sandbox, agent fleet, or crash/interruption resume.

## Rotation and recovery

Ordinary Codex and Claude refreshes are automatic while the account locks are held. For a normal
vendor re-login or deliberate vendor rotation, stop active runs, use the vendor's own login
command, and rerun `agent-loop`; the strictly newer standard generation is validated and installed
atomically before any model call. Use `agent-loop auth init --repair` only after explicit review of
damaged/legacy pair metadata, or for a nonstandard source/custom profile. Never pass a secret on
the command line.

An incomplete Codex transaction is deliberate recovery evidence. On the next locked acquisition,
the runner may promote it only when the durable credential still matches the recorded baseline and
the candidate passes the pinned parser and authentication probe. Ambiguity stops with
`credential_state_conflict`; do not delete, merge, or overwrite competing candidates blindly.
Reauthenticate or reconcile offline according to the operator's account procedure. Run artifacts
normally survive success, failure, timeout, and interruption; credential-tainted or unclassifiable
evidence is instead durably whole-run withheld as described above. Version 1 never continues an
interrupted author turn.

## Development checks

Portable checks do not use secrets or model traffic:

```bash
python3.14 -m pytest -q -m 'not host and not real_cli'
python3.14 -m pytest -q -m 'not real_cli'
python3.14 -m compileall -q src tests
```

Current repository test evidence is `814 passed, 8 skipped`. Separately, the exact installed wheel
passed the installed qualifier's 18 live gates and minted a schema-v3 receipt on the pinned host.
Its digest is recorded outside the packaged documentation in the root-owned install record and
receipt binding. The test count and live
receipt have different scopes, and neither converts the 18 receipt-bound gates into a `78/78`
claim. The implementation is qualified on that pinned binding; specification freeze remains pending
the repository review and change-control record.

Run target-host checks only on the pinned matrix:

```bash
python3.14 -m pytest -q tests/host
```

When the repository's reviewed development tooling is installed, also run:

```bash
ruff format --check .
ruff check .
mypy src tests
```

Pytest's `host` marker denotes pinned Ubuntu/Bubblewrap/systemd behavior. `real_cli` denotes an
explicitly authorized CLI probe using the selected private credential profile. Passing portable
tests does not imply that either marker has passed.

The unfrozen `plan-v1.1` successor is authoritative for current implementation work. Its
implementation qualification has passed on the pinned host, but it must not be frozen or tagged
until the required repository review, merge, and annotated-tag change-control record is complete.
