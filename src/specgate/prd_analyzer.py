from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import OpenQuestion, SpecContract, TestScenarioSpec

ROLE_KEYWORDS = (
    ("学生端", "Student App"),
    ("家长端", "Parent MiniApp"),
    ("教师工作台", "Teacher Workspace"),
    ("学管", "Teacher Workspace"),
    ("运管", "Operations Console"),
    ("后台", "Backend Service"),
    ("服务端", "Backend Service"),
)

STATE_PATTERNS = [
    r"(待审核|已通过|已拒绝|已撤回)",
    r"(待支付|已支付|已退款|部分退课|已取消)",
    r"(待兑换|已兑换|兑换失败|已回退)",
    r"(未开始|学习中(?!心)|离线完成|待同步|已同步|已完成)",
    r"(草稿|待发布|已发布|已下架)",
]


def _extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return fallback


def _extract_actors(text: str) -> list[str]:
    found: list[str] = []
    for kw, normalized in ROLE_KEYWORDS:
        if kw in text and normalized not in found:
            found.append(normalized)
    return found or ["Client", "Backend Service"]


def _extract_states(text: str) -> list[str]:
    states: list[str] = []
    for pattern in STATE_PATTERNS:
        for match in re.findall(pattern, text):
            if match not in states:
                states.append(match)
    return states


def _extract_copy_redlines(text: str) -> list[str]:
    redlines: list[str] = []
    patterns = [
        r"(?:禁止出现|不得出现|不出现|禁用词)[：:\s]*[「“\"']([^」”\"']+)[」”\"']",
        r"文案红线[：:\s]*([^\n。；;]+)",
    ]
    for pat in patterns:
        for match in re.findall(pat, text):
            cleaned = match.strip()
            if cleaned and cleaned not in redlines:
                redlines.append(cleaned)
    return redlines


def _extract_ambiguities(lines: list[str]) -> list[OpenQuestion]:
    questions: list[OpenQuestion] = []
    markers = ("TODO", "TBD", "待确认", "未明确", "待产品确认", "暂未定义")
    idx = 1
    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if any(m in stripped for m in markers) or ("？" in stripped and ("是否" in stripped or "如何" in stripped)):
            questions.append(
                OpenQuestion(
                    question_id=f"AMB-{idx:02d}",
                    topic="Unresolved Requirement Rule",
                    detail=stripped.lstrip("-*> 0123456789."),
                    source_anchor=f"L{line_no}",
                )
            )
            idx += 1
    return questions


def analyze_prd_file(prd_path: str | Path, timestamp: str | None = None) -> SpecContract:
    path = Path(prd_path)
    content = path.read_text(encoding="utf-8")
    source_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    lines = content.splitlines()
    title = _extract_title(content, path.stem)
    actors = _extract_actors(content)
    states = _extract_states(content)
    redlines = _extract_copy_redlines(content)
    ambiguities = _extract_ambiguities(lines)

    scenarios: list[TestScenarioSpec] = []
    seq = 1

    def add_scenario(
        category: str,
        layer: str,
        priority: str,
        sc_title: str,
        preconditions: list[str],
        trigger: str,
        assertions: list[str],
        anchor: str,
        automatable: bool = True,
    ) -> None:
        nonlocal seq
        scenarios.append(
            TestScenarioSpec(
                scenario_id=f"SC-{seq:03d}",
                category=category,
                layer=layer,
                priority=priority,
                title=sc_title,
                preconditions=preconditions,
                trigger=trigger,
                expected_assertions=assertions,
                source_anchor=anchor,
                automatable=automatable,
            )
        )
        seq += 1

    if len(states) >= 2:
        add_scenario(
            category="state_machine",
            layer="L3_API",
            priority="P0",
            sc_title=f"非法状态逆向跃迁与重复提交拦截（{' -> '.join(states[:4])}）",
            preconditions=[f"业务单据已处于终态或后置状态（如 {states[-1]}）"],
            trigger="重放前置状态变更请求或伪造客户端状态字段直接调用提交接口",
            assertions=[
                "服务端必须基于数据库当前状态校验合法迁移路径，拒绝客户端传入的目标状态覆盖",
                "返回明确业务错误码，数据库状态与关联流水保持不变",
            ],
            anchor="states",
        )

    if any(k in content for k in ("积分", "库存", "兑换", "扣减", "拼团", "优惠券", "退款", "并发")):
        add_scenario(
            category="concurrency_consistency",
            layer="L3_API_DB",
            priority="P0",
            sc_title="并发扣减与异常回补事务一致性校验",
            preconditions=["账户余额/库存仅够完成 1 次操作，构造 5 个并发请求同时提交"],
            trigger="并发触发兑换/下单或在中途模拟下游发放失败触发回滚",
            assertions=[
                "至多 1 笔请求成功，其余请求明确失败且不产生超扣或负库存",
                "下游失败时主事务完整回滚，不存在静默吞异常或 0 行更新误判成功",
            ],
            anchor="concurrency",
        )

    if any(k in content for k in ("离线", "同步", "本地缓存", "Room", "断网", "重学", "进度")):
        add_scenario(
            category="offline_sync",
            layer="L1_CLIENT_HARNESS",
            priority="P0",
            sc_title="离线新进度与服务端旧状态同步冲突保护",
            preconditions=["客户端离线完成新单元练习并写入本地库，服务端仍保留较早历史进度"],
            trigger="网络恢复后触发拉取服务端进度与本地待上传队列合并",
            assertions=[
                "较旧的服务端状态不得覆盖本地更新的离线学习记录",
                "空练习批次或残缺记录必须被拒绝提交，不得返回假成功（0 条成功）",
            ],
            anchor="offline_sync",
        )

    if any(k in content for k in ("登录", "名册", "列表", "权限", "学管", "导出", "密码", "手机号")):
        add_scenario(
            category="security_boundary",
            layer="L3_SECURITY",
            priority="P0",
            sc_title="接口鉴权覆盖与响应体敏感字段脱敏核查",
            preconditions=["使用未登录态、低权限角色 Token 及正常角色分别请求新增/变更接口"],
            trigger="调用新增业务路由并检查列表/详情 JSON 响应字段及本地存储",
            assertions=[
                "新增路由前缀必须纳入认证过滤器保护，严禁遗留未受控免鉴权注解",
                "响应 DTO 不得返回 password、payPwd 等敏感字段，前端记住密码不得明文落盘 localStorage",
            ],
            anchor="security",
        )

    for rl in redlines:
        add_scenario(
            category="copy_redline",
            layer="L1_L2_UI",
            priority="P1",
            sc_title=f"端侧文案红线扫描（严禁出现：{rl}）",
            preconditions=["进入对应端侧全部新增页面、弹窗与异常提示态"],
            trigger="扫描前端模板、国际化词条与接口返回提示文案",
            assertions=[f"用户可见界面与错误提示中绝对不包含禁用文案内容（{rl}）"],
            anchor="copy_redline",
        )

    if not scenarios:
        add_scenario(
            category="core_functional",
            layer="L3_API",
            priority="P1",
            sc_title="核心业务主链路与空值边界校验",
            preconditions=["准备标准测试账号与基础业务前置数据"],
            trigger="依次提交合法参数、空集合参数与越界参数",
            assertions=["合法请求状态与持久化落库一致，空集合与非法参数明确拦截"],
            anchor="default",
        )

    created_at = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    contract_id = f"spec_{source_sha[:12]}"
    contract = SpecContract(
        contract_id=contract_id,
        title=title,
        source_path=path.as_posix(),
        source_sha256=source_sha,
        non_executable=True,
        actors=actors,
        states=states,
        copy_redlines=redlines,
        scenarios=scenarios,
        ambiguities=ambiguities,
        created_at=created_at,
    )
    return contract.with_digest()


def contract_to_yaml(contract: SpecContract) -> str:
    lines: list[str] = [
        f'contract_id: "{contract.contract_id}"',
        f'title: "{contract.title}"',
        f'source_path: "{contract.source_path}"',
        f'source_sha256: "{contract.source_sha256}"',
        f"non_executable: {str(contract.non_executable).lower()}",
        f'contract_sha256: "{contract.contract_sha256}"',
        f'created_at: "{contract.created_at}"',
        "actors:",
    ]
    for actor in contract.actors:
        lines.append(f'  - "{actor}"')
    lines.append("states:")
    if contract.states:
        for st in contract.states:
            lines.append(f'  - "{st}"')
    else:
        lines.append("  []")
    lines.append("copy_redlines:")
    if contract.copy_redlines:
        for rl in contract.copy_redlines:
            lines.append(f'  - "{rl}"')
    else:
        lines.append("  []")
    lines.append("scenarios:")
    for sc in contract.scenarios:
        lines.extend(
            [
                f'  - scenario_id: "{sc.scenario_id}"',
                f'    category: "{sc.category}"',
                f'    layer: "{sc.layer}"',
                f'    priority: "{sc.priority}"',
                f'    title: "{sc.title}"',
                f'    trigger: "{sc.trigger}"',
                f"    automatable: {str(sc.automatable).lower()}",
                "    expected_assertions:",
            ]
        )
        for assertion in sc.expected_assertions:
            lines.append(f'      - "{assertion}"')
    lines.append("ambiguities:")
    if contract.ambiguities:
        for amb in contract.ambiguities:
            lines.extend(
                [
                    f'  - question_id: "{amb.question_id}"',
                    f'    source_anchor: "{amb.source_anchor}"',
                    f'    detail: "{amb.detail}"',
                ]
            )
    else:
        lines.append("  []")
    return "\n".join(lines) + "\n"
