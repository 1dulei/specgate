from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .models import CodeEvidence, DiffAuditResult, RiskFinding, Severity


@dataclass(frozen=True)
class AddedLine:
    file_path: str
    line_number: int
    content: str
    hunk_header: str
    hunk_context: str


@dataclass(frozen=True)
class RemovedLine:
    file_path: str
    old_line_number: int
    content: str
    hunk_header: str


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")

# Access-control guards whose *removal* is itself a high-risk change.
AUTH_GUARD_RE = re.compile(
    r"(@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|@SaCheckLogin|@SaCheckRole|@SaCheckPermission"
    r"|@RequiresPermissions|@RequiresRoles|\bcheckPermission\(|\bhasPermission\()"
)
TX_GUARD_RE = re.compile(r"@Transactional\b")


def parse_unified_diff_full(diff_text: str) -> tuple[set[str], list[AddedLine], list[RemovedLine]]:
    files: set[str] = set()
    added: list[AddedLine] = []
    removed: list[RemovedLine] = []
    current_file = "unknown"
    current_line = 0
    current_old_line = 0
    current_hunk = ""
    hunk_lines_map: dict[tuple[str, str], list[str]] = {}
    pending_records: list[tuple[str, int, str, str]] = []

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            target = raw_line[4:].strip()
            if target.startswith("b/"):
                target = target[2:]
            current_file = target
            if current_file != "/dev/null":
                files.add(current_file)
            current_hunk = ""
            continue
        if raw_line.startswith("--- "):
            continue
        m = HUNK_RE.match(raw_line)
        if m:
            current_old_line = int(m.group(1))
            current_line = int(m.group(2))
            current_hunk = raw_line.strip()
            hunk_lines_map.setdefault((current_file, current_hunk), [])
            continue
        if not current_hunk:
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            code = raw_line[1:]
            hunk_lines_map[(current_file, current_hunk)].append(code)
            pending_records.append((current_file, current_line, code, current_hunk))
            current_line += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            removed.append(
                RemovedLine(
                    file_path=current_file,
                    old_line_number=current_old_line,
                    content=raw_line[1:],
                    hunk_header=current_hunk,
                )
            )
            current_old_line += 1
        elif raw_line.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            code = raw_line[1:] if raw_line.startswith(" ") else raw_line
            hunk_lines_map[(current_file, current_hunk)].append(code)
            current_line += 1
            current_old_line += 1

    for fpath, lno, code, hunk in pending_records:
        ctx = "\n".join(hunk_lines_map.get((fpath, hunk), []))
        added.append(AddedLine(file_path=fpath, line_number=lno, content=code, hunk_header=hunk, hunk_context=ctx))

    return files, added, removed


def parse_unified_diff(diff_text: str) -> tuple[set[str], list[AddedLine]]:
    files, added, _ = parse_unified_diff_full(diff_text)
    return files, added


def audit_diff_file(
    diff_path: str | Path,
    extra_copy_redlines: list[str] | None = None,
) -> DiffAuditResult:
    path = Path(diff_path)
    text = path.read_text(encoding="utf-8")
    source_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    files, added_lines, removed_lines = parse_unified_diff_full(text)

    findings: list[RiskFinding] = []
    seen_keys: set[tuple[str, str, int]] = set()
    seq = 1

    # Copy redlines are business-specific: they come from the PRD contract or --redline flags,
    # never from a hardcoded default.
    redlines = [w for w in (extra_copy_redlines or []) if w]

    def emit(
        rule_id: str,
        severity: Severity,
        layer: str,
        title: str,
        summary: str,
        item: AddedLine,
        remediation: str,
        hint: str,
    ) -> None:
        nonlocal seq
        dedup_key = (rule_id, item.file_path, item.line_number)
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)
        findings.append(
            RiskFinding(
                finding_id=f"FG-{seq:03d}",
                rule_id=rule_id,
                severity=severity,
                layer=layer,
                title=title,
                summary=summary,
                evidence=CodeEvidence(
                    file_path=item.file_path,
                    line_number=item.line_number,
                    snippet=item.content.strip(),
                    hunk_header=item.hunk_header,
                ),
                remediation=remediation,
                verification_hint=hint,
            )
        )
        seq += 1

    for item in added_lines:
        stripped = item.content.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue
        ctx = item.hunk_context

        # SG-AUTH-001: Auth bypass / unprotected endpoint
        if re.search(r"@SaIgnore|\.permitAll\(\)|isProtectedPath.*false", stripped):
            emit(
                rule_id="SG-AUTH-001",
                severity=Severity.P0,
                layer="L4_SECURITY",
                title="新增接口或路由存在免鉴权放行风险",
                summary="检测到 @SaIgnore 或显式鉴权豁免，未登录或低权限调用方可能直接触发业务接口。",
                item=item,
                remediation="移除免鉴权注解，将新路由前缀纳入认证拦截器与 @PreAuthorize 权限点校验。",
                hint="使用无 Token 与跨角色 Token 请求该接口，断言返回 401/403。",
            )

        # SG-TRUST-002: Server trusting client-passed status/score/payState
        if re.search(
            r"\.set(Status|PayStatus|OrderStatus|AuditStatus|Passed)\(\s*(req|request|dto|param|body)\.get",
            stripped,
            re.IGNORECASE,
        ):
            emit(
                rule_id="SG-TRUST-002",
                severity=Severity.P0,
                layer="L4_BACKEND",
                title="服务端直接采信客户端上报的业务状态字段",
                summary="直接将请求体中的状态字段写入实体，攻击者或异常客户端可伪造终态绕过服务端流程校验。",
                item=item,
                remediation="忽略客户端传入的目标状态，根据数据库当前状态机与服务端实际核验结果计算下一状态。",
                hint="构造请求直接传入已完成/已支付状态码，验证服务端是否拒绝非法跃迁。",
            )

        # SG-SEC-003: Sensitive credential exposure in VO/DTO or plaintext localStorage
        if re.search(r"(private\s+String\s+(password|payPwd|payPassword)\b|localStorage\.setItem\([^)]*(pwd|password))", stripped, re.IGNORECASE):
            emit(
                rule_id="SG-SEC-003",
                severity=Severity.P0,
                layer="L4_SECURITY",
                title="敏感凭证字段暴露于响应视图或前端明文存储",
                summary="列表/详情返回对象包含密码或支付密码字段，或前端将密码明文写入 localStorage。",
                item=item,
                remediation="从响应 VO/DTO 中彻底移除 password/payPwd 字段；前端仅保存短期受控会话凭证，禁止明文存储密码。",
                hint="抓包检查列表接口 JSON 字段集与浏览器 Application -> LocalStorage 存储内容。",
            )

        # SG-CONC-004: Non-atomic points/stock deduction without row lock / CAS check
        if re.search(r"set(Points|Balance|Stock|RemainCount)\(.*-\s*", stripped) and not re.search(
            r"(for update|cas|version|updateRows|affectedRows|deductWithLock)", ctx, re.IGNORECASE
        ):
            emit(
                rule_id="SG-CONC-004",
                severity=Severity.P1,
                layer="L4_CONCURRENCY",
                title="内存计算扣减余额/库存后直接覆盖写库，存在并发超扣风险",
                summary="采用先查后减再写回模式且未见行锁、乐观锁版本号或受影响行数校验，高并发下会导致超兑或负值。",
                item=item,
                remediation="改用数据库条件原子扣减（WHERE id = ? AND points >= ?）并校验受影响行数 == 1，配合完整回滚事务。",
                hint="使用 5~10 并发线程同时兑换最后 1 件库存商品，检查最终库存与流水条数。",
            )

        # SG-ERR-005: Silent catch block or unchecked updateById
        # Covers bare `updateById(x);`, `accountMapper.updateById(x);` and `this.updateById(x);`
        # when the return value is discarded.
        if re.search(r"catch\s*\([^)]+\)\s*\{\s*(//.*)?\}$", stripped) or re.search(
            r"^\s*(?:[\w$]+\.)*updateById\([^)]*\);\s*$", stripped
        ):
            emit(
                rule_id="SG-ERR-005",
                severity=Severity.P1,
                layer="L4_RELIABILITY",
                title="静默吞异常或未校验数据库更新受影响行数",
                summary="异常被空 catch 吞没或 updateById 返回 0 行时未抛错中断，会导致数据未落库但接口返回成功。",
                item=item,
                remediation="校验更新返回值并在 0 行命中时抛出业务异常触发事务回滚，记录结构化错误日志。",
                hint="模拟并发版本号失效或不存在的记录 ID，确认接口不会返回 200 成功。",
            )

        # SG-SYNC-006: Offline Room/local progress overwritten by older server status
        if re.search(r"(OnConflictStrategy\.REPLACE|statusDao\.overwriteAll|saveServerProgress\()", stripped) and not re.search(
            r"(updatedAt|localTimestamp|pendingUpload|isNewerThan)", ctx
        ):
            emit(
                rule_id="SG-SYNC-006",
                severity=Severity.P1,
                layer="L1_CLIENT_SYNC",
                title="离线同步直接全量覆盖本地状态，未保护未上传的本地新进度",
                summary="拉取服务端状态后直接 REPLACE 覆盖本地库，断网学习产生的新进度会被服务端旧快照回退。",
                item=item,
                remediation="合并前比对本地 pendingUpload 标记与双方 updatedAt 时间戳，保留较新的离线学习进度。",
                hint="构造本地离线完成记录 + 服务端旧记录，运行 Room 内存 Harness 验证合并结果。",
            )

        # SG-DATA-007: Empty batch returning success
        if re.search(r"if\s*\(\s*\w+\.isEmpty\(\)\s*\)\s*return\s+(Result\.ok|Response\.success|0|true)", stripped):
            emit(
                rule_id="SG-DATA-007",
                severity=Severity.P1,
                layer="L3_DATA_INTEGRITY",
                title="空批次数据提交被静默判为成功返回",
                summary="当提交的练习批次或明细列表为空时直接返回成功，前端会误判已完成学习任务并推进状态。",
                item=item,
                remediation="对空批次提交显式返回参数校验错误（400 / 业务错误码），禁止写入完成态。",
                hint="构造空数组批次调用提交 UseCase / 接口，断言拒绝提交且进度不变。",
            )

        # SG-UI-008: Hardcoded counter badge like 0/15
        if re.search(r'["\']0/(1[0-9]|[2-9][0-9])["\']', stripped):
            emit(
                rule_id="SG-UI-008",
                severity=Severity.P2,
                layer="L1_L2_UI",
                title="界面进度或计数标签疑似存在硬编码常量",
                summary="源码中直接写入类似 0/15 的固定字符串，动态课程单元或实际完成数变化时会导致显示失真。",
                item=item,
                remediation="绑定实际已完成数与当前课程总单元数字段，并补充空列表兜底展示。",
                hint="切换不同单元总数的课程包并完成 1 个单元，核对标签分子分母实时刷新。",
            )

        # SG-COPY-009: Copy redline in student-facing client files
        is_student_surface = any(tok in item.file_path.lower() for tok in ("student", "app/", "kid-app", "views/student", "mall"))
        if is_student_surface:
            for word in redlines:
                if word and word in stripped:
                    emit(
                        rule_id="SG-COPY-009",
                        severity=Severity.P2,
                        layer="L1_L2_COPY",
                        title=f"端侧代码触碰禁用文案红线（「{word}」）",
                        summary=f"在面向学生/C 端的模块代码中检测到禁用词「{word}」，违反产品端侧文案隔离规范。",
                        item=item,
                        remediation=f"将面向学生端的展示文案替换为合规表述，移除「{word}」相关字样。",
                        hint="全局检索新增前端模板与弹窗提示文案，确保零命中禁用词清单。",
                    )

    # SG-ERR-005 (multi-line form): `catch (...) {` followed only by blank/comment lines and `}`
    for idx, item in enumerate(added_lines):
        if not re.search(r"catch\s*\([^)]+\)\s*\{\s*$", item.content.strip()):
            continue
        expected_line = item.line_number + 1
        for nxt in added_lines[idx + 1 :]:
            if nxt.file_path != item.file_path or nxt.line_number != expected_line:
                break
            body = nxt.content.strip()
            if not body or body.startswith("//"):
                expected_line += 1
                continue
            if body == "}" or body.startswith("} "):
                emit(
                    rule_id="SG-ERR-005",
                    severity=Severity.P1,
                    layer="L4_RELIABILITY",
                    title="静默吞异常或未校验数据库更新受影响行数",
                    summary="多行空 catch 块吞没了异常，下游失败不会中断流程，接口可能照常返回成功。",
                    item=item,
                    remediation="在 catch 中记录结构化错误日志并抛出业务异常或执行补偿回滚，禁止空块吞异常。",
                    hint="让被调用方抛出异常（如库存服务超时），确认接口不会返回成功且数据已回滚。",
                )
            break

    # Removed-line rules: deleting a guard is as dangerous as adding a bypass.
    added_by_file: dict[str, str] = {}
    for item in added_lines:
        added_by_file[item.file_path] = added_by_file.get(item.file_path, "") + "\n" + item.content

    for rm in removed_lines:
        stripped = rm.content.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue
        readded = added_by_file.get(rm.file_path, "")
        as_item = AddedLine(
            file_path=rm.file_path,
            line_number=rm.old_line_number,
            content=f"[删除行·旧文件第 {rm.old_line_number} 行] {stripped}",
            hunk_header=rm.hunk_header,
            hunk_context="",
        )

        # SG-AUTH-010: Access-control guard removed and not re-added anywhere in the same file
        guard = AUTH_GUARD_RE.search(stripped)
        if guard and guard.group(1) not in readded:
            emit(
                rule_id="SG-AUTH-010",
                severity=Severity.P0,
                layer="L4_SECURITY",
                title="删除了接口权限校验注解/调用，且同文件内未见替代",
                summary=f"本次变更移除了 {guard.group(1).rstrip('(')}，低权限或未登录用户可能直接访问原受保护的接口。",
                item=as_item,
                remediation="确认是否为有意下线权限点；若需保留，恢复注解或在网关/拦截器层补齐等效校验。",
                hint="分别用无 Token、普通角色 Token 调用该接口，断言返回 401/403。",
            )

        # SG-TX-011: @Transactional removed and not re-added in the same file
        if TX_GUARD_RE.search(stripped) and "@Transactional" not in readded:
            emit(
                rule_id="SG-TX-011",
                severity=Severity.P1,
                layer="L4_DATA_INTEGRITY",
                title="删除了事务注解，多步写库可能失去原子性",
                summary="移除 @Transactional 后，方法内多次写库在中途失败时将无法整体回滚，可能留下半完成数据。",
                item=as_item,
                remediation="确认方法是否仍有多表/多步写入；如有，恢复事务注解或改为显式事务模板。",
                hint="在方法第二步写库前注入异常，检查第一步写入是否被回滚。",
            )

    result = DiffAuditResult(
        source_path=path.as_posix(),
        source_sha256=source_sha,
        files_scanned=len(files),
        added_lines_scanned=len(added_lines),
        findings=findings,
    )
    return result.with_digest()
