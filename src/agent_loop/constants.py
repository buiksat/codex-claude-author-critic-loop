"""Frozen support matrix and centrally reviewed version-1 limits."""

from __future__ import annotations

from dataclasses import dataclass

SPEC_VERSION = "plan-v1.0"
SUBJECT_SCHEMA_VERSION = 1
RUN_SCHEMA_VERSION = 1
SANDBOX_PROTOCOL_VERSION = 1
VALIDATION_SCHEMA_VERSION = 1
CRITIC_SCHEMA_VERSION = 1

SUPPORTED_OS_ID = "ubuntu"
SUPPORTED_OS_VERSION = "26.04"
SUPPORTED_MACHINE = "x86_64"
SUPPORTED_PYTHON = (3, 14, 4)
SUPPORTED_GIT_VERSION = "2.53.0"
SUPPORTED_SYSTEMD_VERSION = "259"
SUPPORTED_BASH_VERSION_PREFIX = "5.3."
SUPPORTED_BWRAP_UPSTREAM = "0.11.1"
SUPPORTED_BWRAP_PACKAGE = "0.11.1-1ubuntu0.1"
SUPPORTED_BWRAP_SHA256 = frozenset(
    {"0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0"}
)
SUPPORTED_CODEX_VERSION = "0.144.6"
SUPPORTED_CLAUDE_VERSION = "2.1.215"

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
REGULAR_MODE = 0o100644
EXECUTABLE_MODE = 0o100755
SYMLINK_MODE = 0o120000

DEFAULT_MAX_ROUNDS = 3
DEFAULT_MAX_RUNTIME_SECONDS = 45 * 60
DEFAULT_AUTHOR_TIMEOUT_SECONDS = 15 * 60
DEFAULT_CRITIC_TIMEOUT_SECONDS = 10 * 60
DEFAULT_VALIDATION_TIMEOUT_SECONDS = 10 * 60
DEFAULT_STOP_TIMEOUT_SECONDS = 5

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_ESTIMATED_INPUT_TOKENS = 64_000
DEFAULT_RESERVED_OUTPUT_TOKENS = 8_192
# Version 1 deliberately selects a conservative, model-independent review
# context budget.  A model with a smaller observed context is rejected by the
# capability gate; a larger context does not silently broaden this ceiling.
DEFAULT_REVIEW_CONTEXT_TOKENS = (
    DEFAULT_MAX_ESTIMATED_INPUT_TOKENS + DEFAULT_RESERVED_OUTPUT_TOKENS
)
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_TOTAL_SUBJECT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_PATH_BYTES = 4_096
DEFAULT_MAX_PATH_DEPTH = 128
DEFAULT_MAX_FINDINGS = 128
DEFAULT_MAX_FIELD_BYTES = 32 * 1024
DEFAULT_MAX_AGENT_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RAW_LOG_BYTES = 32 * 1024 * 1024
DEFAULT_WORKSPACE_BYTES = 512 * 1024 * 1024
DEFAULT_MEMORY_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_TASKS_MAX = 256
DEFAULT_LIMIT_FSIZE_BYTES = 64 * 1024 * 1024
DEFAULT_LIMIT_NOFILE = 1024

CLAUDE_MAX_TURNS = 2
CLAUDE_STRUCTURED_OUTPUT_RETRIES = 1
CLAUDE_API_RETRIES = 2
CLAUDE_API_TIMEOUT_MS = 300_000

DEFAULT_PROTECTED_PATTERNS = (
    ".git",
    ".git/**",
    "**/.git",
    "**/.git/**",
    ".codex",
    ".codex/**",
    "AGENTS.md",
    "AGENTS.override.md",
    "**/AGENTS.md",
    "**/AGENTS.override.md",
    ".agent-loop.toml",
)


@dataclass(frozen=True, slots=True)
class Limits:
    """Recorded conservative limits selected within plan-v1.0 freedom."""

    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_subject_bytes: int = DEFAULT_MAX_TOTAL_SUBJECT_BYTES
    max_path_bytes: int = DEFAULT_MAX_PATH_BYTES
    max_path_depth: int = DEFAULT_MAX_PATH_DEPTH
    max_bundle_bytes: int = MAX_BUNDLE_BYTES
    max_estimated_input_tokens: int = DEFAULT_MAX_ESTIMATED_INPUT_TOKENS
    reserved_output_tokens: int = DEFAULT_RESERVED_OUTPUT_TOKENS
    max_findings: int = DEFAULT_MAX_FINDINGS
    max_field_bytes: int = DEFAULT_MAX_FIELD_BYTES
    max_agent_output_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES
    max_raw_log_bytes: int = DEFAULT_MAX_RAW_LOG_BYTES
    workspace_bytes: int = DEFAULT_WORKSPACE_BYTES
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES
    tasks_max: int = DEFAULT_TASKS_MAX
    limit_fsize_bytes: int = DEFAULT_LIMIT_FSIZE_BYTES
    limit_nofile: int = DEFAULT_LIMIT_NOFILE

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_bundle_bytes > MAX_BUNDLE_BYTES:
            raise ValueError("max_bundle_bytes exceeds the frozen 8 MiB ceiling")
        if (
            self.max_estimated_input_tokens + self.reserved_output_tokens
            > DEFAULT_REVIEW_CONTEXT_TOKENS
        ):
            raise ValueError("review input and reserved output exceed the context budget")
