"""Closed protocol for sequential validation inside one sandbox workspace."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from .constants import (
    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
    DEFAULT_MAX_FIELD_BYTES,
    DEFAULT_MAX_RAW_LOG_BYTES,
    DEFAULT_MAX_RUNTIME_SECONDS,
)

VALIDATION_BATCH_SENTINEL = "/opt/agent-loop-runtime/agent_loop/.validation-batch-v1"
MAX_VALIDATION_CHECKS = 128
MAX_VALIDATION_BATCH_RESULT_BYTES = ((DEFAULT_MAX_RAW_LOG_BYTES + 2) // 3) * 4 + 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ValidationBatchCheck:
    check_id: str
    command: str
    timeout_ms: int
    output_max_bytes: int


@dataclass(frozen=True, slots=True)
class ValidationBatchRequest:
    checks: tuple[ValidationBatchCheck, ...]
    max_raw_output_bytes: int


@dataclass(frozen=True, slots=True)
class ValidationBatchRecord:
    index: int
    returncode: int
    timed_out: bool
    output_limited: bool
    process_started: bool
    duration_ms: int
    stdout: bytes
    stderr: bytes


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate validation-batch property {key!r}")
        result[key] = value
    return result


def _object(value: object, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{where} is not one closed object")
    return value


def _json(data: bytes, *, maximum: int) -> dict[str, Any]:
    if not isinstance(data, bytes) or len(data) > maximum:
        raise ValueError("validation-batch protocol input exceeded its byte limit")
    try:
        value = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite validation-batch number {token!r}")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("validation-batch input is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("validation-batch input must be an object")
    return value


def _integer(value: object, minimum: int, maximum: int, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{where} is outside its integer bound")
    return value


def _text(value: object, maximum: int, where: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{where} is empty or unsafe")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{where} is not strict UTF-8 text") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{where} exceeded its byte bound")
    return value


def encode_validation_batch_request(request: ValidationBatchRequest) -> bytes:
    value = {
        "schema_version": 1,
        "kind": "validation_batch_request",
        "max_raw_output_bytes": request.max_raw_output_bytes,
        "checks": [
            {
                "check_id": check.check_id,
                "command": check.command,
                "timeout_ms": check.timeout_ms,
                "output_max_bytes": check.output_max_bytes,
            }
            for check in request.checks
        ],
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    parse_validation_batch_request(encoded)
    return encoded


def parse_validation_batch_request(data: bytes) -> ValidationBatchRequest:
    raw = _object(
        _json(data, maximum=DEFAULT_MAX_AGENT_OUTPUT_BYTES),
        {"schema_version", "kind", "max_raw_output_bytes", "checks"},
        "validation-batch request",
    )
    if raw["schema_version"] != 1 or raw["kind"] != "validation_batch_request":
        raise ValueError("unsupported validation-batch request identity")
    checks_raw = raw["checks"]
    if not isinstance(checks_raw, list) or not 1 <= len(checks_raw) <= MAX_VALIDATION_CHECKS:
        raise ValueError("validation-batch check count is outside its bound")
    checks: list[ValidationBatchCheck] = []
    for index, value in enumerate(checks_raw):
        check = _object(
            value,
            {"check_id", "command", "timeout_ms", "output_max_bytes"},
            f"validation-batch check {index}",
        )
        checks.append(
            ValidationBatchCheck(
                _text(check["check_id"], 256, "validation check ID"),
                _text(check["command"], DEFAULT_MAX_FIELD_BYTES, "validation command"),
                _integer(check["timeout_ms"], 1, DEFAULT_MAX_RUNTIME_SECONDS * 1000, "timeout_ms"),
                _integer(
                    check["output_max_bytes"],
                    1,
                    DEFAULT_MAX_AGENT_OUTPUT_BYTES,
                    "output_max_bytes",
                ),
            )
        )
    if len({check.check_id for check in checks}) != len(checks):
        raise ValueError("validation-batch check IDs are not unique")
    maximum = _integer(
        raw["max_raw_output_bytes"], 1, DEFAULT_MAX_RAW_LOG_BYTES, "max_raw_output_bytes"
    )
    return ValidationBatchRequest(tuple(checks), maximum)


def _b64(value: object, maximum: int, where: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{where} is not base64 text")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"{where} is not canonical base64") from exc
    if base64.b64encode(decoded) != encoded or len(decoded) > maximum:
        raise ValueError(f"{where} is non-canonical or oversized")
    return decoded


def encode_validation_batch_result(records: tuple[ValidationBatchRecord, ...]) -> bytes:
    value = {
        "schema_version": 1,
        "kind": "validation_batch_result",
        "records": [
            {
                "index": record.index,
                "returncode": record.returncode,
                "timed_out": record.timed_out,
                "output_limited": record.output_limited,
                "process_started": record.process_started,
                "duration_ms": record.duration_ms,
                "stdout_b64": base64.b64encode(record.stdout).decode("ascii"),
                "stderr_b64": base64.b64encode(record.stderr).decode("ascii"),
            }
            for record in records
        ],
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(encoded) > MAX_VALIDATION_BATCH_RESULT_BYTES:
        raise ValueError("validation-batch result exceeded its protocol bound")
    return encoded


def parse_validation_batch_result(
    data: bytes, *, expected_checks: int, max_raw_output_bytes: int
) -> tuple[ValidationBatchRecord, ...]:
    raw = _object(
        _json(data, maximum=MAX_VALIDATION_BATCH_RESULT_BYTES),
        {"schema_version", "kind", "records"},
        "validation-batch result",
    )
    if raw["schema_version"] != 1 or raw["kind"] != "validation_batch_result":
        raise ValueError("unsupported validation-batch result identity")
    records_raw = raw["records"]
    if not isinstance(records_raw, list) or not 1 <= len(records_raw) <= expected_checks:
        raise ValueError("validation-batch result count is outside its bound")
    records: list[ValidationBatchRecord] = []
    total = 0
    for index, value in enumerate(records_raw):
        record = _object(
            value,
            {
                "index",
                "returncode",
                "timed_out",
                "output_limited",
                "process_started",
                "duration_ms",
                "stdout_b64",
                "stderr_b64",
            },
            f"validation-batch result {index}",
        )
        if record["index"] != index:
            raise ValueError("validation-batch result indexes are not sequential")
        if not all(
            isinstance(record[name], bool)
            for name in ("timed_out", "output_limited", "process_started")
        ):
            raise ValueError("validation-batch terminal flags are not booleans")
        stdout = _b64(record["stdout_b64"], max_raw_output_bytes, "stdout")
        stderr = _b64(record["stderr_b64"], max_raw_output_bytes, "stderr")
        if not record["process_started"] and (
            not record["timed_out"]
            or record["output_limited"]
            or record["returncode"] != 0
            or record["duration_ms"] != 0
            or stdout
            or stderr
        ):
            raise ValueError("an unstarted validation check has contradictory evidence")
        total += len(stdout) + len(stderr)
        if total > max_raw_output_bytes:
            raise ValueError("validation-batch raw output exceeded its bound")
        records.append(
            ValidationBatchRecord(
                index,
                _integer(record["returncode"], -255, 255, "returncode"),
                record["timed_out"],
                record["output_limited"],
                record["process_started"],
                _integer(
                    record["duration_ms"],
                    0,
                    DEFAULT_MAX_RUNTIME_SECONDS * 1000 + 10_000,
                    "duration_ms",
                ),
                stdout,
                stderr,
            )
        )
    last = records[-1]
    terminal = bool(
        last.timed_out
        or last.output_limited
        or last.returncode < 0
        or last.returncode in {126, 127}
    )
    if len(records) < expected_checks and not terminal:
        raise ValueError("validation-batch result is an unterminated successful prefix")
    return tuple(records)
