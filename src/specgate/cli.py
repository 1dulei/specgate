from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diff_auditor import audit_diff_file
from .eval_runner import run_benchmark
from .gate_evaluator import evaluate_release_gate
from .prd_analyzer import analyze_prd_file, contract_to_yaml
from .report_renderer import render_html_report, render_markdown_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specgate",
        description="SpecGate: Shift-left requirement spec extractor, evidence-bound diff auditor & release gate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_prd = sub.add_parser("analyze-prd", help="Extract non-executable test contract from a Markdown PRD")
    p_prd.add_argument("--prd", required=True, help="Path to PRD markdown file")
    p_prd.add_argument("--format", choices=["json", "yaml"], default="yaml", help="Output format")
    p_prd.add_argument("--out", help="Optional output file path")

    p_diff = sub.add_parser("audit-diff", help="Scan unified git diff for evidence-bound risk findings")
    p_diff.add_argument("--diff", required=True, help="Path to unified diff file")
    p_diff.add_argument("--redline", action="append", default=[], help="Extra copy redline keyword")
    p_diff.add_argument("--out", help="Optional JSON output file path")

    p_gate = sub.add_parser("gate", help="Run full shift-left spec + diff gate and emit reports")
    p_gate.add_argument("--prd", required=True, help="Path to PRD markdown file")
    p_gate.add_argument("--diff", required=True, help="Path to unified diff file")
    p_gate.add_argument("--out-dir", default="output", help="Directory to write contract, verdict, MD and HTML reports")
    p_gate.add_argument("--strict-exit", action="store_true", help="Exit with code 2 when decision is BLOCKED")

    p_eval = sub.add_parser("eval", help="Run built-in benchmark suite against desensitized EdTech cases")
    p_eval.add_argument(
        "--manifest",
        default="evals/manifest.json",
        help="Path to evals manifest.json",
    )
    p_eval.add_argument("--out", help="Optional JSON output path for benchmark summary")

    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze-prd":
        contract = analyze_prd_file(args.prd)
        rendered = (
            json.dumps(contract.to_dict(), ensure_ascii=False, indent=2)
            if args.format == "json"
            else contract_to_yaml(contract)
        )
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return 0

    if args.command == "audit-diff":
        result = audit_diff_file(args.diff, extra_copy_redlines=args.redline)
        rendered = json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return 0

    if args.command == "gate":
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        contract = analyze_prd_file(args.prd)
        audit = audit_diff_file(args.diff, extra_copy_redlines=contract.copy_redlines)
        verdict = evaluate_release_gate(contract, audit)

        (out_dir / "spec-contract.yaml").write_text(contract_to_yaml(contract), encoding="utf-8")
        (out_dir / "spec-contract.json").write_text(
            json.dumps(contract.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "diff-audit.json").write_text(
            json.dumps(audit.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "gate-verdict.json").write_text(
            json.dumps(verdict.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "audit-report.md").write_text(
            render_markdown_report(contract, audit, verdict), encoding="utf-8"
        )
        (out_dir / "audit-report.html").write_text(
            render_html_report(contract, audit, verdict), encoding="utf-8"
        )

        summary = {
            "decision": verdict.decision.value,
            "severity_counts": verdict.severity_counts,
            "scenarios": verdict.scenario_count,
            "output_dir": out_dir.as_posix(),
            "html_report": (out_dir / "audit-report.html").as_posix(),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        if args.strict_exit and verdict.decision.value == "BLOCKED":
            return 2
        return 0

    if args.command == "eval":
        report = run_benchmark(args.manifest)
        rendered = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
