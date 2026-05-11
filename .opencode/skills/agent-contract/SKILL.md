---
name: agent-contract
description: "Agent contract templates for R1 and R2+ rounds, including output format, token budget management, truncation defense, and auto-injection prompt templates."
---

# Agent Contract Skill

> Agent 合约模板 — R1/R2+ 自动注入模板、输出格式、Token 预算、截断防御

## Agent 合约字段（每个 Agent 启动前必须包含）

```
[项目路径]   当前被审计项目根目录的绝对路径（唯一可信锚点）
[搜索路径]   Phase 1 产出的核心代码目录列表
[排除目录]   node_modules, .git, build, dist, target, test, tests, frontend
[工具约束]   搜索用 Grep（ripgrep, 1-3秒）, 文件名用 Glob, 读文件用 Read
             Bash 仅限系统命令（git, mvn, npm, docker）
[禁止写法]   Bash 中的 grep/find/cat（违反 = 10-100x 性能退化）
[调用预算]   工具总调用 ≤400 次, Bash ≤300 次, 超过 200 次开始汇总
[max_turns]  Task 工具的 max_turns 参数
[Turn预留]   turns_used ≥ max_turns - 3 时停止探索，立即产出结构化输出
[超时策略]   Bash timeout ≤30s, Grep 超时→缩小 path→连续失败 2 次→跳过
[审计策略]   sink-driven | control-driven | config-driven
[HARNESS_PROFILE]  语言画像、技术栈画像、场景画像、内部知识状态
[ACTIVE_EXTENSIONS] 已激活 audit-ext-* / audit-vuln-* Skill、激活原因、适用 Agent/维度
[CONTEXT_GAPS] AI 自主探索后仍需人工补充的问题，不阻塞当前审计
[轮次目标]   Round N 的目标函数 + 方法关键词
[前轮输入]   Round N≥2 时的跨轮传递结构
[增量约束]   R2+ 禁止重读 FILES_READ 文件、重复 GREP_DONE 模式
[CANDIDATE_LEDGER] 全局候选账本，记录每个 in-scope Sink/Control/Config candidate 的状态和证据
[输出格式]   结构化摘要（见下方模板）
[截断防御]   HEADER 开头 + AGENT_OUTPUT_END 结尾
```

**项目路径强制规则**:
1. `[项目路径]` 必须是绝对路径，且由主调度器明确注入；不得留空，不得只传项目名。
2. 所有 `[搜索路径]` 都必须是 `[项目路径]` 下的子路径，或能明确解析到 `[项目路径]` 下；禁止在未知 cwd 下做相对搜索。
3. `Read/Grep/Glob` 命中的文件若不在 `[项目路径]` 下，默认视为越界结果，不纳入审计证据。
4. `audit-reports/` 等最终输出路径统一相对 `[项目路径]` 解析；中间候选账本不得写入文件。
5. 若 Agent 未拿到 `[项目路径]`，第一优先级不是继续搜索，而是立即在 HEADER/UNFINISHED 中报告 `project_path_missing`。

---

## Agent Token 预算管理

| 轮次 | Agent 类型 | 数量 | max_turns | 工具调用上限 | 说明 |
|------|-----------|------|-----------|-------------|------|
| R1 | 广度扫描 | 3-5 | 25 | 400 | Grep 定位 + 入口识别 |
| R2 | 增量补漏 | 1-3（按缺口） | 50 | 400 | 只覆盖 R1 缺口 + 数据流深度 |
| R3 | 攻击链验证 | 0-1 | 15 | 400 | 仅有跨模块候选时启动 |

**Token 节约规则**:
1. **定向读取**: Read 用 offset/limit 读取相关代码段（50-100行）
2. **Grep 先行**: 先 Grep 定位行号 → 再 Read 该行号±20行上下文
3. **提前终止**: 同一维度发现 ≥5 个同类漏洞时合并
4. **合并同类**: 同 pattern 多文件 → 1 个发现 + 受影响文件列表

---

## Candidate Ledger 状态机（全局强制）

适用于所有审计策略。覆盖率不再以“读过多少文件”作为主指标，而以每个 in-scope candidate 是否被分类关闭为准。

| candidate_kind | 适用维度 | 候选来源 |
|----------------|----------|----------|
| `SINK` | D1/D4/D5/D6 | 危险 Sink 命中、Source→Sink 链路候选 |
| `CONTROL` | D2/D3/D9 | 认证、授权、业务控制缺失或不一致候选 |
| `CONFIG` | D7/D8/D10 | 配置、加密、供应链风险候选 |

| 状态 | 含义 | 是否计入已分类 |
|------|------|---------------|
| `TRACED_VULN` | 已确认或高置信漏洞，已保存 finding / sink chain | 是 |
| `TRACED_SAFE` | 已追踪 Source/Sink，确认安全边界有效 | 是 |
| `TRACED_SANITIZED` | 存在有效净化/参数化/白名单 | 是 |
| `TRACED_NO_SOURCE` | 未找到真实外部 Source，不能支撑高危结论 | 是 |
| `FALSE_POSITIVE` | Grep 命中但不是真实 Sink | 是 |
| `EXCLUDED_TEST` | 测试/样例代码，已说明排除依据 | 是 |
| `EXCLUDED_VENDOR` | 第三方/vendor/generated 代码，已说明排除依据 | 是 |
| `UNREACHABLE` | 死代码/未注册入口/不可达路径，已说明证据 | 是 |
| `OPEN` | 尚未完成 triage，必须进入 R2 | 否 |
| `TIMEOUT` | 因预算耗尽未完成，必须进入 UNFINISHED / Known Gaps | 否 |

**candidate 100% 覆盖条件**:
- 核心候选类别均已枚举，且 `CANDIDATE_LEDGER` 覆盖全部 in-scope candidate
- `candidate_triage = 已分类 in-scope candidates / 全部 in-scope candidates = 100%`
- `unchecked = OPEN + TIMEOUT = 0`
- Critical/High 候选的 `high_path = 已完成证据链 / 全部高危候选 = 100%`

**落库规则**:
- 若 `audit_save_candidates` 可用，所有 Agent 必须将 `CANDIDATE_LEDGER` 批量写入数据库。
- D1/D4/D5/D6 仍可兼容旧 `audit_save_sink_candidates`，但新流程优先使用 `audit_save_candidates(candidate_kind="SINK")`。
- R2 调度前优先调用 `audit_get_unchecked_candidates` / `audit_get_candidate_coverage` 获取 OPEN/TIMEOUT 和覆盖摘要。
- 禁止把中间候选账本写入 `audit-artifacts/*.jsonl` 或其他文件；落库失败不阻断审计，但必须在 HEADER/UNFINISHED 中说明 `candidate_db_write_failed` 并输出压缩摘要。

---

## Agent 输出模板

> HEADER 段放在最前部，即使 findings 被截断仍可存活。

```
## Agent: {方向名称} | Round {N} | 发现: {数量}

=== HEADER START ===
PROJECT_ROOT: {project_path}
COVERAGE: D1=✅(findings=3,candidate_triage=37/37,unchecked=0,high_path=3/3), D2=⚠️(...), D3=❌, ...
  candidate: candidate_triage=已分类in-scope candidates/全部in-scope candidates; unchecked=OPEN+TIMEOUT; high_path=完整证据链高危候选/全部高危候选
  control-driven(D3/D9): epr=已验证端点数/矩阵总端点数, crud_types=N, control_triage=已分类control candidates/全部control candidates
ACTIVE_EXTENSIONS: {skill=done|partial|skipped(reason)}
UNCHECKED: D1:[file:line|candidate_kind|rule_id|OPEN|reason] | ...
UNFINISHED: {描述}|{原因}, ...
STATS: tools={N}/400 | files_read={N} | grep_patterns={N} | endpoints_audited={N}/{total} | time=~{N}min
=== HEADER END ===

=== TRANSFER BLOCK START ===
FILES_READ: {file1}:{结论} | {file2}:{结论} | ...
GREP_DONE: {pattern1} | {pattern2} | ...
HOTSPOTS: {file:line:断点描述} | ...
=== TRANSFER BLOCK END ===

=== CANDIDATE_LEDGER START ===
SUMMARY: {kind}:{dimension} candidates={N}, in_scope={N}, triaged={N}, unchecked={N}, excluded={N}, high_path={N}/{N}
ITEMS: {file:line|candidate_kind|rule_id|status|reason|finding_id?} | ...  # ≤40项；超过则只放 OPEN/TIMEOUT + 代表性已关闭项
UNCHECKED_CANDIDATES: {file:line|candidate_kind|rule_id|OPEN|next_step} | ...
DB_WRITE: {ok|failed(reason)}
=== CANDIDATE_LEDGER END ===

### 发现列表（表格格式，按严重度排序）

| # | 等级 | 漏洞标题 | 位置 | 关键证据(≤60字) | 数据流 |
|---|------|---------|------|----------------|--------|
| 1 | C | JWT无签名验证 | TokenUtils.java:14 | JWT.decode(token) 无 verify | HTTP→TokenFilter→JWT.decode→ThreadLocal |

### 发现详情（仅 Critical 和高置信 High，每条 ≤5 行）

**[C-01] JWT无签名验证**
代码: `JWT.decode(token)` 替代 `JWT.require(algo).build().verify(token)`
数据流: Request→TokenFilter.doFilter()→TokenUtils.validate()→JWT.decode()
影响: 伪造任意 uid 的 JWT 即可冒充管理员

=== AGENT_OUTPUT_END ===
```

---

## 输出预算规则

- HEADER: ≤ 400 字 + TRANSFER BLOCK: ≤ 400 字（总 800 字）
- CANDIDATE_LEDGER: ≤ 1200 字；完整账本必须优先写入数据库，禁止写入中间 JSONL 文件；对话只输出 OPEN/TIMEOUT 和代表性已关闭项
- 发现表格: 每条 1 行 ≤ 150 字，最多 20 行
- 发现详情: 仅 Critical + 高置信 High，每条 ≤ 10 行，最多 100 条
- **总输出目标: ≤ 5000 字**
- 禁止: 大段原始代码(>3行)、完整文件内容、冗长修复建议

---

## 自动注入模板 — R1

```
---Agent Contract---
0. 项目路径（绝对路径，唯一可信锚点）: {project_path}。
   0.1 先确认所有搜索路径都位于 {project_path} 之下；若缺失/不一致，立即停止扩散搜索，并在 HEADER/UNFINISHED 标记 `project_path_missing` 或 `path_out_of_scope`。
   0.2 最终报告路径（audit-reports）相对 {project_path} 解析，不依赖当前 cwd；中间候选账本不得写入文件。
1. 搜索路径（搜索前先使用Grep工具确认文件完整路径，再使用Read工具读取）: {paths}。排除: {excludes}。
1.1 Harness Profile: {HARNESS_PROFILE}。
1.2 Active Extensions: {ACTIVE_EXTENSIONS}。若存在适用于当前 Agent/维度的扩展 Skill，必须加载并执行其 Agent Contract Additions / Finding Rules / Verification Rules。
1.3 Context Gaps: {CONTEXT_GAPS}。不得因上下文缺失停止审计；用代码证据优先，并在输出中标注未确认假设。
2. 必须使用 Grep/Glob/Read 工具。禁止 Bash 中 grep/find/cat。
3. 40 ≤ 工具调用 ≤ 400 次，Bash ≤ 300 次。max_turns: {N}。
   ★ Turn 预留: turns_used ≥ max_turns-3 时立即停止探索，产出结构化输出。
4. Bash timeout: 30000。Grep 超时→缩小 path→失败 2 次→跳过。
5. 搜索策略: Grep 定位行号 → Read offset/limit 读上下文。禁止整文件读取。
6. 输出: 按 Agent 输出模板返回。禁止大段代码（>5行）。
7. 节约: 同类漏洞 ≥5 合并，只详细描述其中一个漏洞的细节。同 pattern 多文件列清单。
8. 同维度多入口 + CANDIDATE_LEDGER:
   a. 候选类别枚举: ≥1 入口后一次性枚举剩余类别。
   b. 类别上界: 每维度最多 20 个。
   c. 全量候选 triage: 每个 in-scope candidate 必须写入 CANDIDATE_LEDGER 并给出状态。
   d. 深度追踪分层: Critical/High/可疑候选必须补齐对应证据链；明确安全/测试/vendor/误报可分类关闭但必须给理由。
   e. 完整账本必须通过 `audit_save_candidates` 入库；禁止写 audit-artifacts JSONL；对话输出摘要、全部 OPEN/TIMEOUT 和代表性已关闭项。
   f. 禁止用“抽样实例”声明覆盖完成；预算不足时标记 OPEN/TIMEOUT，并写入 UNCHECKED_CANDIDATES。
   g. R1 可产生 UNCHECKED_CANDIDATES；R2+ 只能消化前轮 UNCHECKED_CANDIDATES，不得为逃避覆盖而再生候选。
9. 数据转换管道追踪:
   a. Sink → Grep 调用位置 → 追踪中间构造/转换层
   b. 重复直到 Source 或 5 层上限，每层 Read 验证
   c. 中间层无清洗 → 标记为独立注入入口
10. ★ 截断防御:
    a. 输出以 === HEADER START === 开头
    b. HEADER ≤400 字 + TRANSFER BLOCK ≤400 字
    c. 发现用表格，详情仅 Critical + 高置信 High
    d. 总输出 ≤5000 字
    e. 末尾 === AGENT_OUTPUT_END ===
---End Contract---
```

---

## 自动注入模板 — R2+

```
---Agent Contract (R2+)---
0. 项目路径（绝对路径，唯一可信锚点）: {project_path}。
   0.1 R2+ 继续使用同一 {project_path}；禁止切到父目录、兄弟目录或随机 cwd 补扫。
1-7. [与 R1 相同的基础合约，含 Turn 预留规则]
1.5 Harness Profile / Active Extensions / Context Gaps 继续继承 R1；R2+ 只补未覆盖的扩展检查，不重复已完成扩展规则。
7.5 数据转换管道追踪: 同 R1 #9。优先追踪 HOTSPOTS 中间转换层。
8. 前轮传递:
   COVERED: {dimensions}
   GAPS: {dimensions} ← 审计目标
   CLEAN: {patterns} ← 直接跳过
   HOTSPOTS: {file:line:断点描述} ← 优先深入
   CANDIDATE_LEDGER: {前轮候选账本摘要}
   UNCHECKED_CANDIDATES: {file:line|candidate_kind|rule_id|OPEN/TIMEOUT|next_step} ← R2 优先清空
   FILES_READ: {file:conclusion} ← 不再重读
   GREP_DONE: {pattern} ← 不再重复
9. 增量规则: 只审计 GAPS + UNCHECKED_CANDIDATES。CLEAN 不搜索。FILES_READ 不重读，除非该文件包含待清空 candidate 且必须补上下文。
10. 收敛规则: R2+ 禁止输出新的候选类别；必须把收到的 UNCHECKED_CANDIDATES 分类为最终状态，无法完成则保留 TIMEOUT 并写入 UNFINISHED。
11. ★ 截断防御: 同 R1 #10。
---End Contract---
```
