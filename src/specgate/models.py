from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any


class Severity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class GateDecision(str, Enum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    NEED_REVIEW = "NEED_REVIEW"


def canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TestScenarioSpec:
    scenario_id: str
    category: str
    layer: str
    priority: str
    title: str
    preconditions: list[str]
    trigger: str
    expected_assertions: list[str]
    source_anchor: str
    automatable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OpenQuestion:
    question_id: str
    topic: str
    detail: str
    source_anchor: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SpecContract:
    contract_id: str
    title: str
    source_path: str
    source_sha256: str
    non_executable: bool
    actors: list[str]
    states: list[str]
    copy_redlines: list[str]
    scenarios: list[TestScenarioSpec]
    ambiguities: list[OpenQuestion]
    created_at: str
    contract_sha256: str = ""

    def with_digest(self) -> "SpecContract":
        raw = asdict(self)
        raw.pop("contract_sha256", None)
        digest = canonical_sha256(raw)
        return replace(self, contract_sha256=digest)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CodeEvidence:
    file_path: str
    line_number: int
    snippet: str
    hunk_header: str = ""

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line_number}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["location"] = self.location
        return data


@dataclass(frozen=True)
class RiskFinding:
    finding_id: str
    rule_id: str
    severity: Severity
    layer: str
    title: str
    summary: str
    evidence: CodeEvidence
    remediation: str
    verification_hint: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["evidence"] = self.evidence.to_dict()
        return data


@dataclass(frozen=True)
class DiffAuditResult:
    source_path: str
    source_sha256: str
    files_scanned: int
    added_lines_scanned: int
    findings: list[RiskFinding] = field(default_factory=list)
    audit_sha256: str = ""

    def with_digest(self) -> "DiffAuditResult":
        payload = {
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "files_scanned": self.files_scanned,
            "added_lines_scanned": self.added_lines_scanned,
            "findings": [f.to_dict() for f in self.findings],
        }
        return DiffAuditResult(
            source_path=self.source_path,
            source_sha256=self.source_sha256,
            files_scanned=self.files_scanned,
            added_lines_scanned=self.added_lines_scanned,
            findings=self.findings,
            audit_sha256=canonical_sha256(payload),
        )

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for item in self.findings:
            counts[item.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "files_scanned": self.files_scanned,
            "added_lines_scanned": self.added_lines_scanned,
            "counts_by_severity": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "audit_sha256": self.audit_sha256,
        }


@dataclass(frozen=True)
class GateVerdict:
    decision: GateDecision
    reasons: list[str]
    blocking_findings: list[str]
    unresolved_ambiguities: int
    scenario_count: int
    severity_counts: dict[str, int]
    contract_sha256: str
    audit_sha256: str
    evaluated_at: str
    verdict_sha256: str = ""

    def with_digest(self) -> "GateVerdict":
        payload = {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "blocking_findings": self.blocking_findings,
            "unresolved_ambiguities": self.unresolved_ambiguities,
            "scenario_count": self.scenario_count,
            "severity_counts": self.severity_counts,
            "contract_sha256": self.contract_sha256,
            "audit_sha256": self.audit_sha256,
            "evaluated_at": self.evaluated_at,
        }
        return GateVerdict(
            decision=self.decision,
            reasons=self.reasons,
            blocking_findings=self.blocking_findings,
            unresolved_ambiguities=self.unresolved_ambiguities,
            scenario_count=self.scenario_count,
            severity_counts=self.severity_counts,
            contract_sha256=self.contract_sha256,
            audit_sha256=self.audit_sha256,
            evaluated_at=self.evaluated_at,
            verdict_sha256=canonical_sha256(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data
