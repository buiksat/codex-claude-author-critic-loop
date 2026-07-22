"""One-way conversion from sensitive raw validation output to safe evidence."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from .constants import VALIDATION_SCHEMA_VERSION
from .validation import CheckOutcome, ClassifiedCheck


@dataclass(frozen=True, slots=True)
class KnownSecret:
    identifier: str
    value: bytes

    def __post_init__(self) -> None:
        if not self.identifier or not isinstance(self.value, bytes) or not self.value:
            raise ValueError("known secrets need an identifier and non-empty bytes")

    def forbidden_forms(self) -> tuple[bytes, ...]:
        standard_base64 = base64.b64encode(self.value)
        urlsafe_base64 = base64.urlsafe_b64encode(self.value)
        forms = {
            self.value,
            standard_base64,
            urlsafe_base64,
            standard_base64.rstrip(b"="),
            urlsafe_base64.rstrip(b"="),
            self.value.hex().encode("ascii"),
            self.value.hex().upper().encode("ascii"),
        }
        return tuple(sorted(forms, key=lambda value: (len(value), value)))


@dataclass(frozen=True, slots=True)
class CheckEvidence:
    check_id: str
    exit_code: int | None
    signal: int | None
    baseline_outcome: str | None
    current_outcome: str
    transition: str
    regression: bool
    evidence_complete: bool


@dataclass(frozen=True, slots=True)
class ValidationCriticEvidence:
    schema_version: int
    subject_fingerprint: str
    approval_eligible: bool
    checks: tuple[CheckEvidence, ...]

    def to_json_obj(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "subject_fingerprint": self.subject_fingerprint,
            "approval_eligible": self.approval_eligible,
            "checks": [
                {
                    "check_id": check.check_id,
                    "exit_code": check.exit_code,
                    "signal": check.signal,
                    "baseline_outcome": check.baseline_outcome,
                    "current_outcome": check.current_outcome,
                    "transition": check.transition,
                    "regression": check.regression,
                    "evidence_complete": check.evidence_complete,
                }
                for check in self.checks
            ],
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_json_obj(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )


def raw_log_contains_known_secret(raw_log: bytes, secrets: tuple[KnownSecret, ...]) -> bool:
    """Detect exact/common encoded forms; raw bytes are never returned to an agent."""

    compact = b"".join(raw_log.split())
    lowercase = raw_log.lower()
    compact_lowercase = compact.lower()
    for secret in secrets:
        for form in secret.forbidden_forms():
            if form in raw_log or form.lower() in lowercase:
                return True
            compact_form = b"".join(form.split())
            if compact_form in compact or compact_form.lower() in compact_lowercase:
                return True
    return False


def declassify_validation(
    subject_fingerprint: str,
    checks: tuple[ClassifiedCheck, ...],
    *,
    raw_log: bytes,
    known_secrets: tuple[KnownSecret, ...] = (),
) -> ValidationCriticEvidence:
    """Emit only runner-owned execution metadata; never copy raw log text."""

    # Scan even though no text is forwarded, so callers can record that an
    # optional diagnostic parser must remain disabled for this validation.
    contains_secret = raw_log_contains_known_secret(raw_log, known_secrets)
    evidence = tuple(
        CheckEvidence(
            check_id=check.check_id,
            exit_code=check.exit_code,
            signal=check.signal,
            baseline_outcome=None
            if check.baseline_outcome is None
            else check.baseline_outcome.value,
            current_outcome=check.current_outcome.value,
            transition=check.transition.value,
            regression=check.regression,
            evidence_complete=check.current_outcome in {CheckOutcome.PASSED, CheckOutcome.FAILED},
        )
        for check in checks
    )
    complete = all(item.evidence_complete for item in evidence)
    # A secret-bearing raw log does not make the structured status incomplete;
    # it only prevents optional text diagnostics, which v1 omits by default.
    _ = contains_secret
    return ValidationCriticEvidence(
        schema_version=VALIDATION_SCHEMA_VERSION,
        subject_fingerprint=subject_fingerprint,
        approval_eligible=complete,
        checks=evidence,
    )
