from __future__ import annotations

from datetime import datetime, timezone

from .models import DiffAuditResult, GateDecision, GateVerdict, Severity, SpecContract


def evaluate_release_gate(
    contract: SpecContract,
    audit: DiffAuditResult,
    *,
    max_p2_warnings: int = 2,
    timestamp: str | None = None,
) -> GateVerdict:
    counts = audit.counts_by_severity()
    blocking_ids = [
        f"{f.finding_id}({f.rule_id}@{f.evidence.location})"
        for f in audit.findings
        if f.severity in {Severity.P0, Severity.P1}
    ]
    reasons: list[str] = []

    if blocking_ids:
        decision = GateDecision.BLOCKED
        reasons.append(
            f"检测到 {counts['P0']} 个 P0 阻断级风险与 {counts['P1']} 个 P1 高危代码缺陷，违反准出红线。"
        )
    elif contract.ambiguities:
        decision = GateDecision.NEED_REVIEW
        reasons.append(
            f"需求规格中仍存在 {len(contract.ambiguities)} 项未决规则（TODO/待确认），需人工澄清后再放行。"
        )
    elif counts["P2"] > max_p2_warnings:
        decision = GateDecision.NEED_REVIEW
        reasons.append(
            f"P2 中等风险项共 {counts['P2']} 个（超过阈值 {max_p2_warnings}），需确认规避方案。"
        )
    else:
        decision = GateDecision.PASS
        reasons.append("P0/P1 风险清零，需求测试契约完整，满足版本准出门禁要求。")

    evaluated_at = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdict = GateVerdict(
        decision=decision,
        reasons=reasons,
        blocking_findings=blocking_ids,
        unresolved_ambiguities=len(contract.ambiguities),
        scenario_count=len(contract.scenarios),
        severity_counts=counts,
        contract_sha256=contract.contract_sha256,
        audit_sha256=audit.audit_sha256,
        evaluated_at=evaluated_at,
    )
    return verdict.with_digest()
