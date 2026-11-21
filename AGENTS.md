# AGENTS.md

## Repository Purpose

`SpecGate` is a deterministic, zero-dependency shift-left quality gate tool. It converts Markdown PRDs into non-executable test contracts (`spec-contract.yaml`) and audits unified Git diffs for high-severity multi-end risks with exact `file:line` evidence.

## Core Engineering Rules

1. **Evidence-Bound Findings Only**: Every diff audit finding must carry an exact `file_path`, target `line_number`, and code snippet extracted from the unified diff hunk. Never fabricate file paths or line numbers.
2. **Non-Executable Contract Boundary**: `SpecContract` always sets `non_executable = True`. Planning artifacts must never directly trigger mutating HTTP/DB/device calls without downstream binding approval.
3. **Zero External Runtime Dependencies**: Keep `src/specgate/` strictly on Python 3.11+ standard library so CI runners and local developer machines can run `specgate` without dependency drift.
4. **Benchmark Regression Check**: Whenever adding or modifying risk rules in `src/specgate/diff_auditor.py`, run both unit tests and `specgate eval` to confirm zero false positives on `case_04_clean_release`.

## Verification Commands

```bash
python -m unittest discover -s tests -v
python -m specgate.cli eval --manifest evals/manifest.json
```
