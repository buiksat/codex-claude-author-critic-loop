# agent-loop

`agent-loop` is a containment-first implementation of the frozen
[`plan-v1.0`](PLAN.md) design: Codex is the only code-writing author, Claude is a fresh
tool-disabled critic, and a deterministic Python runner owns validation, limits, evidence, and
stop decisions.

The version-1 implementation paths, portable control plane, executable fake-agent matrix, and
target-host containment components have broad automated coverage. Qualification is nevertheless
incomplete: the required Ruff/strict-mypy gates were unavailable, no clean installation was tested,
and several pinned-CLI behavioral clauses remain unproved. Credentialed
first-turn/resume/model smoke tests were not run, so the runtime is also intentionally blocked by
the live capability-receipt gate. No paid model call is required by installation or the normal test
suite. Do not treat the package as a production security boundary; see
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) for current evidence.

## Frozen support matrix

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
PIP_NO_INDEX=1 pipx install dist/agent_loop-1.0.0-py3-none-any.whl --python python3.14
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

The source distribution retains `PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, and `schemas/` at their
repository-relative paths. A wheel installs the same frozen evidence under
`share/agent-loop/` beneath the installation prefix.

## Credential provisioning

The runner accepts only explicit credential identifiers. It does not import ambient API keys,
`~/.codex`, Claude keychain state, cloud configuration, SSH agents, or a user's complete CLI home.
Credential IDs must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`.

Credential state lives outside retained runs:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/agent-loop/credentials/
├── codex/<id>/
│   ├── auth.json                  # durable file auth, mode 0600
│   ├── lock                       # account-wide lock
│   └── transactions/<run-id>/    # active refresh/resume state
└── claude/<id>/
    └── oauth-token                # dedicated setup-token output, mode 0600
```

Create every credential directory with mode `0700` and every credential file with mode `0600`.
Provision Codex with an explicitly selected and validated file-auth `auth.json`; never point the
runner at an ambient Codex home. Generate a dedicated Claude automation token with
`claude setup-token`, then place only that token in `oauth-token`. Avoid putting either secret on a
command line, in shell history, in project configuration, or in retained artifacts.

One possible offline placement pattern is:

```bash
STATE_ROOT="${XDG_STATE_HOME:-${HOME}/.local/state}"
install -d -m 0700 "$STATE_ROOT/agent-loop/credentials/codex/author-account"
install -d -m 0700 "$STATE_ROOT/agent-loop/credentials/claude/critic-token"
install -m 0600 /secure/input/codex-auth.json \
  "$STATE_ROOT/agent-loop/credentials/codex/author-account/auth.json"
install -m 0600 /secure/input/claude-setup-token \
  "$STATE_ROOT/agent-loop/credentials/claude/critic-token/oauth-token"
```

The `/secure/input/...` files are operator-managed examples, not ambient CLI locations. Check the
final ownership and modes before use. The Codex account lock is held across first and resumed turns;
a validated refresh is atomically reconciled to the durable file.

## Configuration and commands

The command interface is:

```bash
agent-loop --state-home /home/bahram/.local/state run \
  --task task.md \
  --check '/usr/bin/python3.14 -m pytest -q' \
  --codex-executable \
    /home/bahram/.npm-global/lib/node_modules/@openai/codex/bin/codex.js \
  --claude-executable /home/bahram/.local/share/claude/versions/2.1.215 \
  --author-model gpt-5.4-codex \
  --author-effort high \
  --critic-model claude-opus-4-6 \
  --critic-effort medium \
  --codex-credential-id author-account \
  --claude-credential-id critic-token
agent-loop --state-home /home/bahram/.local/state status <run-id>
agent-loop --state-home /home/bahram/.local/state show <run-id> [--round N]
```

The executable paths above are the detected reviewed installs; the model choices are explicit
receipt-bound selections, not moving aliases. The command is copy-paste complete after `task.md`,
the two named credential stores, and the matching live-capability receipt described below exist. On
a different reviewed installation, replace the absolute paths and exact models consistently in
both the live gates and the run command; an old receipt will intentionally stop matching.

`status` reports bounded run state. `show` reports the retained run manifest and structured round
summaries; raw sensitive logs remain separate. There is intentionally no run-level `resume`
command. Exact Codex thread resume occurs only inside one healthy in-process run.

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

author_model = "gpt-5.4-codex"
author_effort = "high"
critic_model = "claude-opus-4-6"
critic_effort = "medium"
codex_credential_id = "author-account"
claude_credential_id = "critic-token"

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
review context, reviewed read-only toolchain paths, exact model/effort values, timeouts, and
credential IDs. Run `agent-loop run --help` for the concrete spelling.

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

Production runs require a fresh private receipt proving the eleven receipt-bound target-host and
paid/live acceptance gates for the exact host and selections. That receipt is necessary, but is not
by itself proof of all 72 acceptance contracts or completion of the static-analysis, pinned-Claude
retry, and clean-install work listed in the status document. The tests never infer ambient
credentials or installations. On the detected frozen host, an operator who has
independently provisioned the managed Claude boundary can set every required selector explicitly:

```bash
export AGENT_LOOP_ALLOW_LIVE=1
export AGENT_LOOP_CONFIRM_PAID_CODEX=1
export AGENT_LOOP_CONFIRM_PAID_CLAUDE=1
export AGENT_LOOP_STATE_HOME=/home/bahram/.local/state

export AGENT_LOOP_CODEX_CREDENTIAL_ID=author-account
export AGENT_LOOP_CODEX_INSTALL_ROOT=/home/bahram/.npm-global/lib/node_modules/@openai/codex
export AGENT_LOOP_CODEX_INSTALL_RELATIVE=bin/codex.js
export AGENT_LOOP_CODEX_PATH=/home/bahram/.npm-global/lib/node_modules/@openai/codex/bin/codex.js
export AGENT_LOOP_CODEX_MODEL=gpt-5.4-codex
export AGENT_LOOP_CODEX_EFFORT=high

export AGENT_LOOP_CLAUDE_CREDENTIAL_ID=critic-token
export AGENT_LOOP_CLAUDE_INSTALL_ROOT=/home/bahram/.local/share/claude/versions
export AGENT_LOOP_CLAUDE_INSTALL_RELATIVE=2.1.215
export AGENT_LOOP_CLAUDE_MODEL=claude-opus-4-6
export AGENT_LOOP_CLAUDE_EFFORT=medium
export AGENT_LOOP_CLAUDE_MANAGED_POLICY_PROBE=attested-v1
export AGENT_LOOP_CLAUDE_MANAGED_PROBE_ID=reviewed-managed-boundary-v1

python3.14 -m pytest -q tests/host tests/real_cli
```

The two `AGENT_LOOP_CONFIRM_PAID_*` variables authorize real model traffic: Codex first-turn and
exact-resume calls plus a Claude review call. The managed-policy variables are not a substitute for
the boundary. An administrator must first provision the reviewed managed hook/status/file-suggestion
process described by the skipped test and make its non-secret attestation available to the exact
Claude install and system-policy mounts.

At pytest session finish, a receipt is written only if target-host gates 8/9/10/11/29/30/71, the
combined Codex gates 33/65/66, and Claude gate 49 truly pass, including exact observed model/effort
assertions. Every required setup/call/teardown phase must pass in the same pytest session, with no
skip, xfail, xpass, failure, or missing gate. The session ledger is reset at session start, so
results from separate invocations cannot be combined. The harness then re-runs the full production
preflight and re-hashes the exact reviewed Codex and Claude install closures plus the
location-independent runtime Python-source closure before writing:

```text
/home/bahram/.local/state/agent-loop/capabilities/live-v1.json
```

The containing directory is mode `0700` and the receipt is mode `0600`. It contains no credential
bytes. It is valid for at most seven days and binds the exact OS/kernel/Python/Git/systemd/Bash and
Bubblewrap facts and probes, executable and install-closure hashes, credential identifiers,
requested models, and requested efforts. Production reconstructs that binding from its current
preflight; any mismatch, stale timestamp, unsafe metadata, or absent receipt stops before spending.

No paid or live model call was run while implementing or documenting this revision, so this work did
not mint a receipt. Do not set the live gates until all portable, fake-agent, and target-host tests
pass and the operator has explicitly authorized the exact accounts, models, timeouts, and calls. A
skipped or xfailed test is not a successful smoke test.

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
capture, a generated sanitized Codex home, exact thread-ID routing, fresh tool-disabled Claude
reviews, no network for model-generated commands/Git/validation/critic tools, and one fresh bounded
tmpfs for each complete ordered validation suite. Checks in a suite run sequentially in that shared
workspace, with descendants cleaned between checks; author execution remains a separate sandbox.
The trusted Codex and Claude control processes retain normal host egress for authentication and
model traffic; version 1 does not provide hostname allowlisting.

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
- `openat2`, Bubblewrap, systemd user services, and the trusted supervisor are Linux security
  boundaries, not portable conveniences.
- There is no automatic commit, push, PR, publication, direct-checkout mode, linked worktree,
  alternate sandbox, agent fleet, or crash/interruption resume.

## Rotation and recovery

Rotate credentials only while no run holds the account lock. Replace the durable Codex `auth.json`
or Claude `oauth-token` with a newly validated mode-`0600` file using a same-directory atomic
replacement, then rerun non-model authentication/capability probes before spending.

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

At this revision, pytest collected 540 tests; 514 portable tests and 22 host-marked tests passed,
and the combined non-real-CLI selection passed 536 tests. These results do not include the four
real-CLI nodes. The two non-model Codex probes were also run separately; the credentialed Codex and
Claude model nodes were not run.

Run target-host checks only on the frozen matrix:

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
explicitly authorized CLI probe and may require dedicated credential identifiers. Passing portable
tests does not imply that either marker has passed.

The frozen specification is authoritative. A change that weakens a boundary belongs in a reviewed
successor specification, not a compatibility fallback.
