from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from specgate.cli import main as cli_main
from specgate.diff_auditor import audit_diff_file, parse_unified_diff
from specgate.eval_runner import run_benchmark
from specgate.gate_evaluator import evaluate_release_gate
from specgate.models import GateDecision
from specgate.prd_analyzer import analyze_prd_file, contract_to_yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


class SpecGateTestSuite(unittest.TestCase):
    def test_prd_analyzer_extracts_states_redlines_and_digest(self) -> None:
        prd_path = REPO_ROOT / "evals" / "fixtures" / "case_01_mall_redemption" / "prd.md"
        contract = analyze_prd_file(prd_path, timestamp="2026-11-18T00:00:00Z")

        self.assertTrue(contract.non_executable)
        self.assertIn("待兑换", contract.states)
        self.assertIn("已兑换", contract.states)
        self.assertIn("校区", contract.copy_redlines)
        self.assertGreaterEqual(len(contract.scenarios), 4)
        self.assertEqual(len(contract.contract_sha256), 64)

        yaml_text = contract_to_yaml(contract)
        self.assertIn("non_executable: true", yaml_text)
        self.assertIn("SC-001", yaml_text)

    def test_prd_ambiguity_triggers_need_review_when_diff_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            prd = tdir / "ambiguous.md"
            prd.write_text(
                "# 课程退费规则调整\n\n状态：待支付 -> 已支付 -> 已退款。\n- TODO：部分退课时赠品积分是否扣回待产品确认\n",
                encoding="utf-8",
            )
            diff = REPO_ROOT / "evals" / "fixtures" / "case_04_clean_release" / "changes.diff"

            contract = analyze_prd_file(prd)
            self.assertEqual(len(contract.ambiguities), 1)
            audit = audit_diff_file(diff, extra_copy_redlines=contract.copy_redlines)
            verdict = evaluate_release_gate(contract, audit)
            self.assertEqual(verdict.decision, GateDecision.NEED_REVIEW)

    def test_diff_parser_tracks_exact_target_line_numbers(self) -> None:
        diff_path = REPO_ROOT / "evals" / "fixtures" / "case_01_mall_redemption" / "changes.diff"
        files, added = parse_unified_diff(diff_path.read_text(encoding="utf-8"))
        self.assertEqual(len(files), 3)

        audit = audit_diff_file(diff_path, extra_copy_redlines=["校区"])
        by_rule = {f.rule_id: f for f in audit.findings}
        self.assertIn("SG-AUTH-001", by_rule)
        self.assertEqual(by_rule["SG-AUTH-001"].evidence.line_number, 18)
        self.assertIn("SG-TRUST-002", by_rule)
        self.assertIn("SG-CONC-004", by_rule)
        self.assertIn("SG-ERR-005", by_rule)
        self.assertIn("SG-COPY-009", by_rule)

    def test_benchmark_reports_honest_seed_and_hard_case_results(self) -> None:
        manifest = REPO_ROOT / "evals" / "manifest.json"
        report = run_benchmark(manifest)
        self.assertEqual(report.total_cases, 10)

        # Seed cases were written together with the rules, so they must stay green.
        self.assertEqual(report.by_group["seed"].fully_correct_cases, 4)

        # Hard cases lock in both the fixes and the documented limitations.
        by_case = {c.case_id: c for c in report.cases}
        self.assertEqual(by_case["case_05_removed_auth"].detected_rules, ["SG-AUTH-010"])
        self.assertEqual(by_case["case_06_mapper_multiline_catch"].detected_rules, ["SG-ERR-005"])
        self.assertEqual(by_case["case_09_auth_moved_to_class"].detected_rules, [])
        # Known limitations (see README "已知局限"): if a future change fixes these, update the README too.
        self.assertEqual(by_case["case_07_indirect_status_trust"].false_negatives, 1)
        self.assertEqual(by_case["case_08_display_calc_safe"].false_positives, 1)
        self.assertEqual(by_case["case_10_room_replace_with_merge"].false_positives, 1)
        self.assertEqual(report.by_group["hard"].fully_correct_cases, 3)

    def test_removed_auth_guard_reports_old_line_number(self) -> None:
        diff_path = REPO_ROOT / "evals" / "fixtures" / "case_05_removed_auth" / "changes.diff"
        audit = audit_diff_file(diff_path)
        self.assertEqual(len(audit.findings), 1)
        finding = audit.findings[0]
        self.assertEqual(finding.rule_id, "SG-AUTH-010")
        self.assertEqual(finding.evidence.line_number, 24)
        self.assertIn("删除行", finding.evidence.snippet)

    def test_no_hardcoded_copy_redline_without_prd(self) -> None:
        diff_path = REPO_ROOT / "evals" / "fixtures" / "case_01_mall_redemption" / "changes.diff"
        audit = audit_diff_file(diff_path)
        self.assertNotIn("SG-COPY-009", {f.rule_id for f in audit.findings})

    def test_cli_gate_generates_artifacts_and_strict_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prd = str(REPO_ROOT / "evals" / "fixtures" / "case_02_offline_sync" / "prd.md")
            diff = str(REPO_ROOT / "evals" / "fixtures" / "case_02_offline_sync" / "changes.diff")

            exit_code = cli_main(["gate", "--prd", prd, "--diff", diff, "--out-dir", tmp, "--strict-exit"])
            self.assertEqual(exit_code, 2)

            out_dir = Path(tmp)
            self.assertTrue((out_dir / "spec-contract.yaml").exists())
            self.assertTrue((out_dir / "gate-verdict.json").exists())
            self.assertTrue((out_dir / "audit-report.md").exists())
            self.assertTrue((out_dir / "audit-report.html").exists())

            verdict_data = json.loads((out_dir / "gate-verdict.json").read_text(encoding="utf-8"))
            self.assertEqual(verdict_data["decision"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
