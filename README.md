# SpecGate

提测前的「需求测试契约 + 代码变更风险」检查工具（Python 3.11 标准库实现，无第三方运行时依赖）。

> **项目定位**：这是一个个人开源项目。思路来自我在多端（学习平板 / Web 后台 / 服务端）测试工作中反复遇到的提测期缺陷，代码与样例均为脱敏后重新实现，**不包含任何公司代码或数据**。

## 为什么做

很多高危缺陷在需求评审和提测 `git diff` 阶段就能发现：新接口漏挂鉴权、删掉了权限注解、服务端直接采信客户端传来的状态、积分先查后减没加锁、平板离线学习进度被服务端旧数据覆盖……

直接把 diff 贴给大模型审查，结果不稳定，还经常给出没有行号依据的泛泛建议。SpecGate 把这些高频问题固化成**确定性规则**，每条风险都附带 `文件:行号`、修复建议和验证方法，可以直接接入 CI。

## 核心能力

1. **需求测试契约提取（`analyze-prd`）**
   从 Markdown 需求文档中提取角色端侧、状态流转、端侧禁用文案和未决项（`TODO` / `待确认`），生成标记为 `non_executable: true` 的测试契约，并附 SHA-256 摘要用于变更比对。
2. **代码变更风险审计（`audit-diff`）**
   解析 Unified Diff，同时检查**新增行**和**删除行**，共 11 条规则：

   | 规则 | 级别 | 检查内容 |
   | :--- | :---: | :--- |
   | `SG-AUTH-001` | P0 | 新增 `@SaIgnore` / `permitAll()` 等鉴权豁免 |
   | `SG-AUTH-010` | P0 | **删除**了 `@PreAuthorize` / `@SaCheckPermission` 等权限校验，且同文件内未重新添加 |
   | `SG-TRUST-002` | P0 | `setStatus(req.getStatus())` 这类直接采信客户端状态 |
   | `SG-SEC-003` | P0 | VO 暴露 `password` / `payPwd` 字段，或前端 `localStorage` 明文存密码 |
   | `SG-CONC-004` | P1 | 余额/积分/库存内存计算后写回，附近未见行锁、版本号或受影响行数校验 |
   | `SG-ERR-005` | P1 | 空 `catch`（单行或多行），或 `xxxMapper.updateById(...)` 丢弃返回值 |
   | `SG-SYNC-006` | P1 | 离线场景用 `REPLACE` 全量覆盖本地数据，附近未见时间戳比较 |
   | `SG-DATA-007` | P1 | 空批次提交直接返回成功 |
   | `SG-TX-011` | P1 | **删除**了 `@Transactional` 且同文件内未重新添加 |
   | `SG-UI-008` | P2 | 界面计数硬编码（如 `"0/15"`） |
   | `SG-COPY-009` | P2 | 端侧代码命中禁用文案（禁用词来自 PRD 或 `--redline` 参数，**不内置任何业务词**） |

3. **准入/准出判定（`gate`）**：综合风险级别和需求未决项，给出 `PASS` / `BLOCKED` / `NEED_REVIEW`，输出 JSON、Markdown 和 HTML 报告；`--strict-exit` 在 `BLOCKED` 时返回退出码 `2`。
4. **评测集（`eval`）**：内置 10 个脱敏样例，输出准确率、精确率、召回率。

## 评测结果（如实公布）

| 分组 | 用例数 | 完全正确 | 说明 |
| :--- | :---: | :---: | :--- |
| `seed` 种子样例 | 4 | 4 | 和规则一起编写，**只能证明规则能跑通，不能证明泛化能力** |
| `hard` 难例 | 6 | 3 | 规则写完后专门补的反例，用来暴露盲区 |
| **合计** | 10 | 7 | 判定准确率 0.70 · 宏平均精确率 0.70 · 召回率 0.90 |

难例里的失败项见下方「已知局限」。补充删除行检测、`mapper.updateById` 和多行空 `catch` 识别之前，6 个难例只能做对 1 个。

```bash
specgate eval --manifest evals/manifest.json
```

## 快速上手

```bash
pip install -e .

# 完整门禁：需求契约 + diff 审计 + 判定 + 报告
specgate gate \
  --prd evals/fixtures/case_01_mall_redemption/prd.md \
  --diff evals/fixtures/case_01_mall_redemption/changes.diff \
  --out-dir output/mall_audit --strict-exit

# 单独提取需求契约
specgate analyze-prd --prd evals/fixtures/case_02_offline_sync/prd.md --format yaml

# 单元测试
python -m unittest discover -s tests -v
```

## 设计取舍

- **用正则而不是 AST**：目标是零依赖、秒级跑完、规则人人看得懂、改得动。代价是只能看到单行和同一 diff 块内的上下文（见局限）。
- **契约与执行分离**：PRD 提取出的契约固定标记 `non_executable: true`，只作为测试设计和准出核对依据，不直接驱动任何写操作。
- **宁可漏报，也要每条都有行号**：每个风险都必须能定位到具体文件和行号，不输出"建议加强异常处理"这类无法落地的结论。

## 已知局限

| 局限 | 对应难例 | 可能的改进方向 |
| :--- | :--- | :--- |
| 状态值先赋给局部变量再写入，就识别不出来（间接采信） | `case_07` 漏报 | 做简单的变量来源追踪，或引入 AST |
| 只读接口在 VO 里做减法计算，会被误报为并发扣减 | `case_08` 误报 | 区分"写入实体后持久化"与"仅组装返回对象" |
| 合并逻辑在另一个文件里时，DAO 的 `REPLACE` 仍会被误报 | `case_10` 误报 | 支持跨文件上下文，或允许在配置里标记已审查的 DAO |
| PRD 解析基于关键词，只识别预设的几组状态词 | — | 状态词表改为可配置；可选接入 LLM 做补充抽取 |
| 只分析 diff，看不到未改动的代码 | — | 支持传入仓库路径读取完整文件 |

## 目录结构

```text
specgate/
├── src/specgate/          # 需求解析、diff 规则、门禁判定与报告渲染
├── evals/                 # 10 个脱敏样例（4 个种子 + 6 个难例）
├── skills/specgate-audit/ # 可挂载到 AI 编程助手的 Agent Skill
├── tests/                 # 单元测试与 CLI 集成测试
└── AGENTS.md
```

## License

MIT
