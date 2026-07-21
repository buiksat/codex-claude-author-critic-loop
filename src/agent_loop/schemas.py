"""Versioned trust-boundary parsers and critic semantic validation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Never

from .constants import (
    CRITIC_SCHEMA_VERSION,
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    DEFAULT_MAX_FIELD_BYTES,
    DEFAULT_MAX_FINDINGS,
)
from .errors import AgentLoopError, StopReason, fail

_SEVERITY_VALUES = ("critical", "high", "medium", "low")
_CATEGORY_VALUES = (
    "correctness",
    "security",
    "reliability",
    "performance",
    "maintainability",
    "testing",
    "spec_compliance",
)
SEVERITIES = frozenset(_SEVERITY_VALUES)
CATEGORIES = frozenset(_CATEGORY_VALUES)
_FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class Verdict(StrEnum):
    LGTM = "LGTM"
    REVISE = "REVISE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    severity: str
    category: str
    file: str | None
    symbol: str | None
    line_start: int | None
    line_end: int | None
    problem: str
    evidence: str
    required_fix: str


@dataclass(frozen=True, slots=True)
class CriticReview:
    schema_version: int
    verdict: Verdict
    summary: str
    blocked_reason: str | None
    blocking_findings: tuple[Finding, ...]
    non_blocking_findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class ApprovalContext:
    all_validations_pass: bool
    semantic_deltas_visible: bool
    evidence_approval_eligible: bool


def critic_schema_document() -> dict[str, Any]:
    """Return the exact closed JSON Schema passed to the pinned Claude CLI."""

    nullable_text = {
        "anyOf": [
            {"type": "null"},
            {"type": "string", "minLength": 1, "maxLength": DEFAULT_MAX_FIELD_BYTES},
        ]
    }
    finding = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "id",
            "severity",
            "category",
            "file",
            "symbol",
            "line_start",
            "line_end",
            "problem",
            "evidence",
            "required_fix",
        ],
        "properties": {
            "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"},
            "severity": {"enum": list(_SEVERITY_VALUES)},
            "category": {"enum": list(_CATEGORY_VALUES)},
            "file": {"type": ["string", "null"], "maxLength": DEFAULT_MAX_FIELD_BYTES},
            "symbol": {"type": ["string", "null"], "maxLength": DEFAULT_MAX_FIELD_BYTES},
            "line_start": {"type": ["integer", "null"], "minimum": 1},
            "line_end": {"type": ["integer", "null"], "minimum": 1},
            "problem": {"type": "string", "minLength": 1, "maxLength": DEFAULT_MAX_FIELD_BYTES},
            "evidence": {"type": "string", "minLength": 1, "maxLength": DEFAULT_MAX_FIELD_BYTES},
            "required_fix": {
                "type": "string",
                "minLength": 1,
                "maxLength": DEFAULT_MAX_FIELD_BYTES,
            },
        },
    }
    verdict_invariants = [
        {
            "if": {
                "properties": {"verdict": {"const": "LGTM"}},
                "required": ["verdict"],
            },
            "then": {
                "properties": {
                    "blocked_reason": {"type": "null"},
                    "blocking_findings": {"type": "array", "maxItems": 0},
                }
            },
        },
        {
            "if": {
                "properties": {"verdict": {"const": "REVISE"}},
                "required": ["verdict"],
            },
            "then": {
                "properties": {
                    "blocked_reason": {"type": "null"},
                    "blocking_findings": {"type": "array", "minItems": 1},
                }
            },
        },
        {
            "if": {
                "properties": {"verdict": {"const": "BLOCKED"}},
                "required": ["verdict"],
            },
            "then": {
                "properties": {
                    "blocked_reason": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": DEFAULT_MAX_FIELD_BYTES,
                        "pattern": r"\S",
                    },
                    "blocking_findings": {"type": "array", "maxItems": 0},
                }
            },
        },
    ]
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://agent-loop.invalid/schemas/critic-v1.schema.json",
        "title": "agent-loop critic output v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "verdict",
            "summary",
            "blocked_reason",
            "blocking_findings",
            "non_blocking_findings",
        ],
        "properties": {
            "schema_version": {"const": CRITIC_SCHEMA_VERSION},
            "verdict": {"enum": ["LGTM", "REVISE", "BLOCKED"]},
            "summary": {
                "type": "string",
                "minLength": 1,
                "maxLength": DEFAULT_MAX_FIELD_BYTES,
            },
            "blocked_reason": nullable_text,
            "blocking_findings": {
                "type": "array",
                "maxItems": DEFAULT_MAX_FINDINGS,
                "items": {"$ref": "#/definitions/finding"},
            },
            "non_blocking_findings": {
                "type": "array",
                "maxItems": DEFAULT_MAX_FINDINGS,
                "items": {"$ref": "#/definitions/finding"},
            },
        },
        "allOf": verdict_invariants,
        "definitions": {"finding": finding},
    }


def critic_schema_json() -> str:
    return json.dumps(
        critic_schema_document(),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _invalid(detail: str) -> Never:
    raise fail(StopReason.INVALID_STRUCTURED_OUTPUT, detail)


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid(f"duplicate JSON property: {key!r}")
        result[key] = value
    return result


def parse_json_object(
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_AGENT_OUTPUT_BYTES,
) -> dict[str, Any]:
    if len(data) > max_bytes:
        raise fail(StopReason.AGENT_OUTPUT_LIMIT, "JSON envelope exceeded its byte limit")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=lambda token: _invalid(f"non-finite JSON number: {token}"),
        )
    except AgentLoopError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        _invalid(f"invalid UTF-8 JSON: {exc}")
    if not isinstance(value, dict):
        _invalid("top-level JSON value must be an object")
    return value


def extract_structured_output(envelope_data: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the complete Claude envelope, then extract only its top-level review."""

    envelope = parse_json_object(envelope_data)
    if envelope.get("is_error") is True or envelope.get("type") == "error":
        _invalid("Claude returned an error envelope")
    if "structured_output" not in envelope:
        _invalid("Claude envelope has no top-level structured_output")
    review = envelope["structured_output"]
    if not isinstance(review, dict):
        _invalid("structured_output must be an object")
    return envelope, review


def _closed_mapping(value: object, required: set[str], *, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _invalid(f"{where} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required
    if missing:
        _invalid(f"{where} is missing properties: {sorted(missing)!r}")
    if unknown:
        _invalid(f"{where} has unknown properties: {sorted(unknown)!r}")
    if not all(isinstance(key, str) for key in value):
        _invalid(f"{where} property names must be strings")
    return value


def _string(
    value: object,
    *,
    where: str,
    nullable: bool = False,
    allow_empty: bool = False,
) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        _invalid(f"{where} must be a string" + (" or null" if nullable else ""))
    if not allow_empty and not value.strip():
        _invalid(f"{where} cannot be empty")
    if len(value.encode("utf-8")) > DEFAULT_MAX_FIELD_BYTES:
        _invalid(f"{where} exceeds its UTF-8 byte limit")
    return value


def _nullable_positive_int(value: object, *, where: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _invalid(f"{where} must be a positive integer or null")
    return value


_FINDING_KEYS = {
    "id",
    "severity",
    "category",
    "file",
    "symbol",
    "line_start",
    "line_end",
    "problem",
    "evidence",
    "required_fix",
}


def _finding(value: object, *, where: str) -> Finding:
    raw = _closed_mapping(value, _FINDING_KEYS, where=where)
    finding_id = _string(raw["id"], where=f"{where}.id")
    assert finding_id is not None
    if _FINDING_ID.fullmatch(finding_id) is None:
        _invalid(f"{where}.id has an invalid format")
    severity = _string(raw["severity"], where=f"{where}.severity")
    category = _string(raw["category"], where=f"{where}.category")
    assert severity is not None and category is not None
    if severity not in SEVERITIES:
        _invalid(f"{where}.severity is not in the closed enum")
    if category not in CATEGORIES:
        _invalid(f"{where}.category is not in the closed enum")
    file = _string(raw["file"], where=f"{where}.file", nullable=True)
    symbol = _string(raw["symbol"], where=f"{where}.symbol", nullable=True)
    line_start = _nullable_positive_int(raw["line_start"], where=f"{where}.line_start")
    line_end = _nullable_positive_int(raw["line_end"], where=f"{where}.line_end")
    if (line_start is None) != (line_end is None):
        _invalid(f"{where} line range must be wholly null or wholly specified")
    if line_start is not None and line_end is not None and line_end < line_start:
        _invalid(f"{where} line range is reversed")
    problem = _string(raw["problem"], where=f"{where}.problem")
    evidence = _string(raw["evidence"], where=f"{where}.evidence")
    required_fix = _string(raw["required_fix"], where=f"{where}.required_fix")
    assert problem is not None and evidence is not None and required_fix is not None
    return Finding(
        finding_id,
        severity,
        category,
        file,
        symbol,
        line_start,
        line_end,
        problem,
        evidence,
        required_fix,
    )


def _findings(value: object, *, where: str) -> tuple[Finding, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _invalid(f"{where} must be an array")
    if len(value) > DEFAULT_MAX_FINDINGS:
        _invalid(f"{where} has too many findings")
    findings = tuple(_finding(item, where=f"{where}[{index}]") for index, item in enumerate(value))
    ids = [finding.finding_id for finding in findings]
    if len(ids) != len(set(ids)):
        _invalid(f"{where} contains duplicate finding IDs")
    return findings


_REVIEW_KEYS = {
    "schema_version",
    "verdict",
    "summary",
    "blocked_reason",
    "blocking_findings",
    "non_blocking_findings",
}


def validate_critic_review(
    value: object,
    *,
    approval: ApprovalContext | None = None,
) -> CriticReview:
    raw = _closed_mapping(value, _REVIEW_KEYS, where="structured_output")
    version = raw["schema_version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CRITIC_SCHEMA_VERSION
    ):
        _invalid("unsupported critic schema_version")
    verdict_raw = _string(raw["verdict"], where="structured_output.verdict")
    try:
        verdict = Verdict(verdict_raw)
    except ValueError:
        _invalid("verdict is not in the closed enum")
    summary = _string(raw["summary"], where="structured_output.summary")
    blocked_reason = _string(
        raw["blocked_reason"],
        where="structured_output.blocked_reason",
        nullable=True,
    )
    blocking = _findings(raw["blocking_findings"], where="structured_output.blocking_findings")
    non_blocking = _findings(
        raw["non_blocking_findings"], where="structured_output.non_blocking_findings"
    )
    all_ids = [finding.finding_id for finding in (*blocking, *non_blocking)]
    if len(all_ids) != len(set(all_ids)):
        _invalid("finding IDs must be unique across both arrays")

    if verdict is Verdict.LGTM:
        if blocking or blocked_reason is not None:
            _invalid("LGTM requires no blocking findings and a null blocked_reason")
        if approval is not None and not (
            approval.all_validations_pass
            and approval.semantic_deltas_visible
            and approval.evidence_approval_eligible
        ):
            raise fail(
                StopReason.CRITIC_LGTM_WITH_FAILED_VALIDATION,
                "LGTM contradicted locally proven approval predicates",
            )
    elif verdict is Verdict.REVISE:
        if not blocking:
            _invalid("REVISE requires at least one blocking finding")
        if blocked_reason is not None:
            _invalid("REVISE requires a null blocked_reason")
    else:
        if blocked_reason is None:
            _invalid("BLOCKED requires blocked_reason")
        if blocking:
            _invalid("BLOCKED cannot contain blocking findings")

    assert summary is not None
    return CriticReview(version, verdict, summary, blocked_reason, blocking, non_blocking)


def parse_critic_envelope(
    data: bytes,
    *,
    approval: ApprovalContext | None = None,
) -> tuple[dict[str, Any], CriticReview]:
    envelope, value = extract_structured_output(data)
    return envelope, validate_critic_review(value, approval=approval)
