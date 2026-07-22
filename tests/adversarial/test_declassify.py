import base64

from tests.unit.test_validation import summary

from agent_loop.declassify import KnownSecret, declassify_validation, raw_log_contains_known_secret
from agent_loop.validation import classify_validations


def test_069_validation_log_exfiltration() -> None:
    value = b"super-secret-value"
    secret = KnownSecret("fixture", value)
    forms = (
        value,
        base64.b64encode(value),
        value.hex().encode(),
        b"super- secret- value",
    )
    checks = classify_validations(summary(0), summary(1))
    for raw in forms:
        evidence = declassify_validation("a" * 64, checks, raw_log=raw, known_secrets=(secret,))
        encoded = evidence.to_json_bytes()
        assert value not in encoded
        assert base64.b64encode(value) not in encoded
        assert value.hex().encode() not in encoded
    assert raw_log_contains_known_secret(base64.b64encode(value), (secret,))
