from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .diff_auditor import audit_diff_file
from .gate_evaluator import evaluate_release_gate
from .prd_analyzer import analyze_prd_file


@dataclass(frozen=True)
class CaseEvalScore:
    case_id: str
    title: str
    group: str
    expected_decision: str
    actual_decision: str
    decision_match: bool
    expected_rules: list[str]
    detected_rules: list[str]
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float


@dataclass(frozen=True)
class GroupSummary:
    total_cases: int
    fully_correct_cases: int
    decision_accuracy: float


@dataclass(frozen=True)
class BenchmarkReport:
    total_cases: int
    decision_accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    by_group: dict[str, GroupSummary]
    cases: list[CaseEvalScore]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_benchmark(manifest_path: str | Path) -> BenchmarkReport:
    mpath = Path(manifest_path)
    base_dir = mpath.parent
    manifest = json.loads(mpath.read_text(encoding="utf-8"))

    scores: list[CaseEvalScore] = []
    for item in manifest["cases"]:
        case_dir = base_dir / item["dir"]
        contract = analyze_prd_file(case_dir / "prd.md", timestamp="2026-11-18T00:00:00Z")
        audit = audit_diff_file(case_dir / "changes.diff", extra_copy_redlines=contract.copy_redlines)
        verdict = evaluate_release_gate(contract, audit, timestamp="2026-11-18T00:00:00Z")

        expected_set = set(item["expected_rules"])
        detected_set = {f.rule_id for f in audit.findings}

        tp = len(expected_set & detected_set)
        fp = len(detected_set - expected_set)
        fn = len(expected_set - detected_set)

        precision = tp / (tp + fp) if (tp + fp) else (1.0 if not expected_set else 0.0)
        recall = tp / (tp + fn) if (tp + fn) else 1.0

        scores.append(
            CaseEvalScore(
                case_id=item["case_id"],
                title=item["title"],
                group=item.get("group", "default"),
                expected_decision=item["expected_decision"],
                actual_decision=verdict.decision.value,
                decision_match=(verdict.decision.value == item["expected_decision"]),
                expected_rules=sorted(expected_set),
                detected_rules=sorted(detected_set),
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=round(precision, 4),
                recall=round(recall, 4),
            )
        )

    total = len(scores)
    acc = sum(1 for s in scores if s.decision_match) / total if total else 0.0
    mp = sum(s.precision for s in scores) / total if total else 0.0
    mr = sum(s.recall for s in scores) / total if total else 0.0
    mf1 = (2 * mp * mr / (mp + mr)) if (mp + mr) else 0.0

    by_group: dict[str, GroupSummary] = {}
    for g in sorted({s.group for s in scores}):
        members = [s for s in scores if s.group == g]
        fully = sum(1 for s in members if s.decision_match and s.false_positives == 0 and s.false_negatives == 0)
        by_group[g] = GroupSummary(
            total_cases=len(members),
            fully_correct_cases=fully,
            decision_accuracy=round(sum(1 for s in members if s.decision_match) / len(members), 4),
        )

    return BenchmarkReport(
        total_cases=total,
        decision_accuracy=round(acc, 4),
        macro_precision=round(mp, 4),
        macro_recall=round(mr, 4),
        macro_f1=round(mf1, 4),
        by_group=by_group,
        cases=scores,
    )
