---
name: specgate-audit
description: Evidence-bound shift-left PRD test contract extractor and multi-repo Git diff risk gate. Use before starting QA execution or before merging feature branches across Backend (Java/Spring), Android (Kotlin/Room), and Web (Vue/TS) repositories.
---

# SpecGate Audit Skill

## When to Use

Activate this skill when:
1. Reviewing a new PRD to extract state transitions, role boundaries, copy redlines, and unresolved product rules (`TODO` / `TBD`) before writing test cases.
2. Auditing a feature branch `git diff` across Backend, Android, and Web repos to catch high-severity defects before manual or automated execution.
3. Evaluating release readiness (`PASS` / `BLOCKED` / `NEED_REVIEW`) with `file:line` evidence.

## Workflow

1. Generate the diff for the target branch against the baseline commit/branch:
   ```bash
   git diff <base-sha>..<head-sha> > changes.diff
   ```
2. Run SpecGate full gate:
   ```bash
   specgate gate --prd path/to/prd.md --diff changes.diff --out-dir output/specgate
   ```
3. Inspect `output/specgate/gate-verdict.json` and `output/specgate/audit-report.html`:
   - Report only findings backed by `file:line` snippets.
   - Keep `spec-contract.yaml` (`non_executable: true`) separate from runtime test execution bindings until human review confirms open questions.
