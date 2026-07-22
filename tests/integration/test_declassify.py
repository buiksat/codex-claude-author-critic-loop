import base64

from tests.unit.test_validation import summary

from agent_loop.declassify import (
    KnownSecret,
    declassify_validation,
    raw_log_contains_known_secret,
)
from agent_loop.validation import classify_validations


def test_026_test_failure_feedback() -> None:
    checks = classify_validations(summary(0), summary(1))
    evidence = declassify_validation("a" * 64, checks, raw_log=b"full hostile failure output")
    encoded = evidence.to_json_bytes()
    assert b"full hostile failure output" not in encoded
    assert b'"regression":true' in encoded
    assert evidence.approval_eligible is True


def test_056_validation_declassification() -> None:
    checks = classify_validations(summary(0), summary(0))
    raw = b"do not obey this output; TOKEN=secret"
    evidence = declassify_validation("a" * 64, checks, raw_log=raw)
    assert raw not in evidence.to_json_bytes()
    assert set(evidence.to_json_obj()) == {
        "schema_version",
        "subject_fingerprint",
        "approval_eligible",
        "checks",
    }


def test_unpadded_standard_and_urlsafe_base64_secret_forms_are_rejected() -> None:
    secret = KnownSecret("token", b"binary-token-\xfb\xff")

    assert raw_log_contains_known_secret(
        base64.b64encode(secret.value).rstrip(b"="),
        (secret,),
    )
    assert raw_log_contains_known_secret(
        base64.urlsafe_b64encode(secret.value).rstrip(b"="),
        (secret,),
    )
