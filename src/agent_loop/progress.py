"""Exact normalized non-success fingerprints and adjacent-state stall detection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class ValidationProgress:
    check_id: str
    outcome: str
    transition: str
    regression: bool
    evidence_complete: bool


@dataclass(frozen=True, slots=True, order=True)
class FindingProgress:
    finding_id: str
    severity: str
    category: str
    file: str | None
    line_start: int | None
    line_end: int | None
    problem: str
    evidence: str
    required_fix: str


@dataclass(frozen=True, slots=True)
class ProgressState:
    subject_fingerprint: str
    validations: tuple[ValidationProgress, ...]
    verdict: str
    blocking_findings: tuple[FindingProgress, ...] = ()
    blocked_reason: str | None = None

    def canonical_bytes(self) -> bytes:
        payload = {
            "blocked_reason": self.blocked_reason,
            "blocking_findings": [
                {
                    "category": finding.category,
                    "evidence": finding.evidence,
                    "file": finding.file,
                    "id": finding.finding_id,
                    "line_end": finding.line_end,
                    "line_start": finding.line_start,
                    "problem": finding.problem,
                    "required_fix": finding.required_fix,
                    "severity": finding.severity,
                }
                for finding in sorted(self.blocking_findings)
            ],
            "subject_fingerprint": self.subject_fingerprint,
            "validations": [
                {
                    "check_id": validation.check_id,
                    "evidence_complete": validation.evidence_complete,
                    "outcome": validation.outcome,
                    "regression": validation.regression,
                    "transition": validation.transition,
                }
                for validation in sorted(self.validations)
            ],
            "verdict": self.verdict,
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(b"agent-loop-progress-v1\0" + self.canonical_bytes()).hexdigest()


@dataclass(slots=True)
class StallDetector:
    previous_fingerprint: str | None = None

    def observe(self, state: ProgressState) -> bool:
        """Return true for the second adjacent identical non-success state."""

        current = state.fingerprint
        repeated = self.previous_fingerprint == current
        self.previous_fingerprint = current
        return repeated
