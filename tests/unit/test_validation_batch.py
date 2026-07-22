from __future__ import annotations

import json

import pytest

from agent_loop.validation_batch import (
    ValidationBatchCheck,
    ValidationBatchRecord,
    ValidationBatchRequest,
    encode_validation_batch_request,
    encode_validation_batch_result,
    parse_validation_batch_request,
    parse_validation_batch_result,
)


def test_validation_batch_protocol_round_trips_binary_streams() -> None:
    request = ValidationBatchRequest(
        (ValidationBatchCheck("tests", "pytest -q", 1_000, 4_096),),
        8_192,
    )
    assert parse_validation_batch_request(encode_validation_batch_request(request)) == request

    records = (ValidationBatchRecord(0, 1, False, False, True, 25, b"out\x00", b"err\xff"),)
    encoded = encode_validation_batch_result(records)
    assert (
        parse_validation_batch_result(
            encoded,
            expected_checks=1,
            max_raw_output_bytes=8_192,
        )
        == records
    )


def test_validation_batch_protocol_rejects_unknown_and_duplicate_properties() -> None:
    request = {
        "schema_version": 1,
        "kind": "validation_batch_request",
        "max_raw_output_bytes": 1,
        "checks": [
            {
                "check_id": "one",
                "command": "true",
                "timeout_ms": 1,
                "output_max_bytes": 1,
                "unknown": True,
            }
        ],
    }
    with pytest.raises(ValueError, match="closed object"):
        parse_validation_batch_request(json.dumps(request).encode())
    duplicate = b'{"schema_version":1,"schema_version":1}'
    with pytest.raises(ValueError, match="strict UTF-8 JSON"):
        parse_validation_batch_request(duplicate)


def test_validation_batch_result_rejects_nonsequential_indexes_and_raw_overflow() -> None:
    records = (ValidationBatchRecord(1, 0, False, False, True, 1, b"a", b""),)
    with pytest.raises(ValueError, match="indexes are not sequential"):
        parse_validation_batch_result(
            encode_validation_batch_result(records),
            expected_checks=2,
            max_raw_output_bytes=2,
        )
    records = (ValidationBatchRecord(0, 0, False, False, True, 1, b"ab", b""),)
    with pytest.raises(ValueError, match="oversized"):
        parse_validation_batch_result(
            encode_validation_batch_result(records),
            expected_checks=1,
            max_raw_output_bytes=1,
        )


def test_validation_batch_result_rejects_successful_prefix_and_accepts_terminal_prefix() -> None:
    successful = (ValidationBatchRecord(0, 0, False, False, True, 1, b"", b""),)
    with pytest.raises(ValueError, match="unterminated successful prefix"):
        parse_validation_batch_result(
            encode_validation_batch_result(successful),
            expected_checks=2,
            max_raw_output_bytes=1,
        )

    terminal = (ValidationBatchRecord(0, 0, True, False, False, 0, b"", b""),)
    assert (
        parse_validation_batch_result(
            encode_validation_batch_result(terminal),
            expected_checks=2,
            max_raw_output_bytes=1,
        )
        == terminal
    )
