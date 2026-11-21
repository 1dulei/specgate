from __future__ import annotations

import html

from .models import DiffAuditResult, GateDecision, GateVerdict, SpecContract


def render_markdown_report(
    contract: SpecContract,
    audit: DiffAuditResult,
    verdict: GateVerdict,
) -> str:
    badge = {
        GateDecision.PASS: "PASS（准许放行）",
        GateDecision.BLOCKED: "BLOCKED（门禁拦截）",
        GateDecision.NEED_REVIEW: "NEED_REVIEW（需人工复核）",
    }[verdict.decision]

    lines: list[str] = [
        f"# SpecGate 质量门禁审计报告 · {contract.title}",
        "",
        f"- **门禁结论**：`{badge}`",
        f"- **评估时间**：`{verdict.evaluated_at}`",
        f"- **契约摘要 SHA-256**：`{contract.contract_sha256[:16]}...`",
        f"- **代码审计 SHA-256**：`{audit.audit_sha256[:16]}...`",
        f"- **风险分布**：P0={verdict.severity_counts['P0']} | P1={verdict.severity_counts['P1']} | P2={verdict.severity_counts['P2']} | P3={verdict.severity_counts['P3']}",
        "",
        "## 1. 门禁判定依据",
        "",
    ]
    for r in verdict.reasons:
        lines.append(f"- {r}")

    lines.extend(["", "## 2. 分支代码风险证据清单（Evidence-Bound Findings）", ""])
    if not audit.findings:
        lines.append("本次变更扫描未发现命中高危规则的代码片段。")
    else:
        lines.append("| 编号 | 级别 | 规则 ID | 位置 (`file:line`) | 风险说明与修复方向 |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in audit.findings:
            lines.append(
                f"| `{f.finding_id}` | **{f.severity.value}** | `{f.rule_id}` | `{f.evidence.location}` | {f.title}：{f.remediation} |"
            )

    lines.extend(["", "## 3. 左移测试规格契约（Non-Executable Test Contract）", ""])
    for sc in contract.scenarios:
        lines.append(f"### `{sc.scenario_id}` [{sc.priority} / {sc.layer}] {sc.title}")
        lines.append(f"- **触发动作**：{sc.trigger}")
        for a in sc.expected_assertions:
            lines.append(f"- **断言要求**：{a}")
        lines.append("")

    if contract.ambiguities:
        lines.extend(["## 4. 待产品/研发澄清事项", ""])
        for amb in contract.ambiguities:
            lines.append(f"- `{amb.question_id}` ({amb.source_anchor})：{amb.detail}")

    return "\n".join(lines).rstrip() + "\n"


def render_html_report(
    contract: SpecContract,
    audit: DiffAuditResult,
    verdict: GateVerdict,
) -> str:
    status_color = {
        GateDecision.PASS: "#10B981",
        GateDecision.BLOCKED: "#EF4444",
        GateDecision.NEED_REVIEW: "#F59E0B",
    }[verdict.decision]

    findings_html = ""
    if not audit.findings:
        findings_html = '<div class="empty">本次变更未命中高危代码规则。</div>'
    else:
        cards = []
        for f in audit.findings:
            sev_color = "#EF4444" if f.severity.value == "P0" else ("#F97316" if f.severity.value == "P1" else "#EAB308")
            cards.append(
                f"""
                <div class="row-item">
                  <div class="row-head">
                    <div>
                      <span class="sev" style="color:{sev_color};border-color:{sev_color}40">{html.escape(f.severity.value)}</span>
                      <span class="mono rule">{html.escape(f.rule_id)}</span>
                      <strong>{html.escape(f.title)}</strong>
                    </div>
                    <span class="mono loc">{html.escape(f.evidence.location)}</span>
                  </div>
                  <p class="desc">{html.escape(f.summary)}</p>
                  <pre class="code">{html.escape(f.evidence.snippet)}</pre>
                  <div class="fix">修复建议：{html.escape(f.remediation)}</div>
                </div>
                """
            )
        findings_html = "\n".join(cards)

    scenarios_html = "\n".join(
        f"""
        <div class="row-item">
          <div class="row-head">
            <span><span class="mono rule">{html.escape(sc.scenario_id)}</span> <strong>{html.escape(sc.title)}</strong></span>
            <span class="mono loc">{html.escape(sc.layer)} · {html.escape(sc.priority)}</span>
          </div>
          <p class="desc">触发：{html.escape(sc.trigger)}</p>
          <ul class="assertions">
            {''.join(f'<li>{html.escape(a)}</li>' for a in sc.expected_assertions)}
          </ul>
        </div>
        """
        for sc in contract.scenarios
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SpecGate Audit · {html.escape(contract.title)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: #0D0E11;
      color: #EDEDEF;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
      line-height: 1.6;
    }}
    .wrap {{ max-width: 820px; margin: 0 auto; padding: 48px 24px 72px; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .top {{ display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid #1E2028; padding-bottom: 20px; margin-bottom: 28px; }}
    .badge {{ font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 999px; border: 1px solid {status_color}; color: {status_color}; }}
    h1 {{ font-size: 22px; margin: 0 0 6px; font-weight: 600; letter-spacing: -0.01em; }}
    h2 {{ font-size: 14px; color: #8A8F98; text-transform: uppercase; letter-spacing: 0.06em; margin: 36px 0 14px; font-weight: 600; }}
    .meta {{ color: #8A8F98; font-size: 13px; }}
    .summary-bar {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
    .stat {{ background: #12141A; border: 1px solid #1E2028; border-radius: 6px; padding: 12px 14px; }}
    .stat-label {{ font-size: 12px; color: #7E848E; }}
    .stat-val {{ font-size: 18px; font-weight: 600; margin-top: 2px; }}
    .reason {{ background: #12141A; border-left: 3px solid {status_color}; padding: 12px 16px; font-size: 13px; color: #D4D7DD; margin-bottom: 8px; }}
    .row-item {{ border-top: 1px solid #1E2028; padding: 16px 0; }}
    .row-head {{ display: flex; justify-content: space-between; align-items: baseline; gap: 12px; font-size: 14px; }}
    .sev {{ font-size: 11px; font-weight: 700; padding: 1px 6px; border: 1px solid; border-radius: 4px; margin-right: 6px; }}
    .rule {{ color: #8A8F98; font-size: 12px; margin-right: 6px; }}
    .loc {{ color: #7E848E; font-size: 12px; }}
    .desc {{ margin: 8px 0; font-size: 13px; color: #A0A6B1; }}
    .code {{ background: #13151C; border: 1px solid #222631; border-radius: 4px; padding: 8px 12px; font-size: 12px; overflow-x: auto; color: #E2E8F0; margin: 8px 0; }}
    .fix {{ font-size: 12px; color: #10B981; }}
    .assertions {{ margin: 6px 0 0; padding-left: 18px; font-size: 13px; color: #C5CAD3; }}
    .footer {{ margin-top: 44px; padding-top: 16px; border-top: 1px solid #1E2028; display: flex; justify-content: space-between; font-size: 12px; color: #62666D; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>{html.escape(contract.title)}</h1>
        <div class="meta mono">contract={html.escape(contract.contract_sha256[:12])} · audit={html.escape(audit.audit_sha256[:12])} · files={audit.files_scanned}</div>
      </div>
      <span class="badge mono">{html.escape(verdict.decision.value)}</span>
    </div>

    <div class="summary-bar mono">
      <div class="stat"><div class="stat-label">P0 Blocker</div><div class="stat-val" style="color:#EF4444">{verdict.severity_counts['P0']}</div></div>
      <div class="stat"><div class="stat-label">P1 Critical</div><div class="stat-val" style="color:#F97316">{verdict.severity_counts['P1']}</div></div>
      <div class="stat"><div class="stat-label">P2 Warning</div><div class="stat-val" style="color:#EAB308">{verdict.severity_counts['P2']}</div></div>
      <div class="stat"><div class="stat-label">Spec Scenarios</div><div class="stat-val">{verdict.scenario_count}</div></div>
    </div>

    {''.join(f'<div class="reason">{html.escape(r)}</div>' for r in verdict.reasons)}

    <h2>Evidence-Bound Diff Findings ({len(audit.findings)})</h2>
    {findings_html}

    <h2>Shift-Left Spec Contract ({len(contract.scenarios)})</h2>
    {scenarios_html}

    <div class="footer mono">
      <span>SpecGate v0.3.0 · Non-Executable Spec + Evidence-Bound Gate</span>
      <span>verdict_sha256={html.escape(verdict.verdict_sha256[:16])}</span>
    </div>
  </div>
</body>
</html>
"""
