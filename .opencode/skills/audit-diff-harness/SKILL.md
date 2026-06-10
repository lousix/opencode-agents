---
name: audit-diff-harness
description: "Feature-centric deep incremental security review harness for Git-backed code changes, with autonomous, agents, and hybrid execution modes."
---

# Audit Diff Harness Skill

> 功能中心的 Git 增量深度安全检视协议。核心目标: 审计一个由多个 commit / PR / patch 实现的功能，而不是孤立审查几行 diff。

## Core Principles

```text
增量审计只有 deep。
默认由 AI 自主漏洞挖掘，D1-D10 只作为审后覆盖矩阵。
Agent 是可选放大镜，不是默认探索边界。
功能语义是审计边界，Git diff 是证据入口。
功能文档是上下文，不是漏洞成立证据。
```

最终 finding 必须同时绑定:
- 功能语义: 该漏洞属于哪个功能、破坏了哪个预期安全属性
- Git 变更: changed file / changed hunk / changed control / changed dependency
- 代码证据: 真实 source、broken control、sink、配置或依赖边界
- 可达性: 攻击者如何通过该功能触发

## Supported Inputs

### Required Feature Boundary

优先要求用户给出功能名或功能说明:

```text
/git-audit --feature "报表导出" --range main..HEAD
/git-audit --feature "SSO 登录改造" --commits a1b2c3,d4e5f6
/git-audit --feature "支付回调接入" --patch patches/payment.diff --docs specs/payment.md
```

自然语言也可接受:

```text
审计这次“批量导入客户”功能，代码在 PR 21、22、25，需求文档在 docs/import-customer.md
```

若未提供功能名，调度器必须从 branch 名、commit message、PR 标题、diff 文件名和变更模块推断 `[FEATURE_PROFILE]`，并把 `feature_name_inferred` 写入 `[CONTEXT_GAPS]`。

### Code Scope Inputs

支持以下 Git-backed 范围:

| 输入 | 含义 |
|------|------|
| `--worktree` | staged + unstaged + untracked，本地工作区整体改动 |
| `--staged` | 只审暂存区 |
| `--unstaged` | 未暂存改动 + untracked |
| `--commit <sha>` | 审单个 commit，对比 `<sha>^..<sha>` |
| `--commits a,b,c` | 审一组 commit；用于一个功能分散在多个提交 |
| `--range <base>..<head>` | 审 revision range |
| `--base <ref> --head <ref>` | 显式 base/head |
| `--merge-base <base> <head>` | 使用 merge-base 作为 base |
| `--patch <file.diff>` | 审离线 patch |
| `--prs 1,2,3` | 可选解析器；若无法解析，要求用户提供 branch/range/patch |

### Optional Context Inputs

| 输入 | 用途 |
|------|------|
| `--docs <paths>` | 功能需求、设计、接口、权限矩阵、测试计划 |
| `--focus D1,D3,D9` | 用户指定重点，但不能跳过明显相关风险 |
| `--engine autonomous|agents|hybrid` | 执行模式，默认 `autonomous` |
| `--include/--exclude` | 限制或排除路径 |
| `{target}/audit-context.md` | 项目级技术栈、暴露面、内部框架语义 |
| `.codegraph/` / `.code-review-graph/` | 可选图上下文，补充 impact radius / affected flows |

## Execution Modes

### `autonomous` (default)

主审计 AI 自主完成漏洞挖掘:

```text
feature intent
  -> expected security properties
  -> trust boundaries
  -> implementation diff
  -> supporting code
  -> source/control/sink proof
  -> exploitability and severity
```

D1-D10 在该模式下只用于审后 coverage self-check 和报告分类。

### `agents`

结构化并行审计。调度器根据 `[FEATURE_SECURITY_PROFILE]` 启动相关专业 Agent:

| 风险信号 | Agent |
|----------|-------|
| injection / query / template / expression | `audit-d1-injection` |
| auth / permission / ownership / workflow | `audit-d2d3d9-control` |
| deserialization / RCE / script engine | `audit-d4-rce` |
| file / archive / download / outbound URL | `audit-d5d6-file-ssrf` |
| crypto / config / dependency / CI | `audit-d7d8d10-config` |

每个 Agent 必须只审 `[FEATURE_PROFILE] + [DIFF_SCOPE] + [RELEVANT_SUPPORTING_FILES]`，不得扩散为全仓库审计。

### `hybrid`

自主主线 + 定向 Agent。主审计 AI 先自由建模和发现风险，再把高风险簇派给对应 Agent 深挖或复核。

## Required Output Blocks

调度器在进入漏洞挖掘前必须生成:

```text
[FEATURE_PROFILE]
name: {provided|inferred feature name}
intent: {what capability is added or changed}
actors: {anonymous|user|admin|service|third_party|unknown}
assets: {data, files, credentials, money, tenant data, control plane}
entrypoints: {routes, jobs, consumers, CLI, callbacks, config toggles}
trust_boundaries: {internet->app, user->tenant data, service callback->internal, ...}
security_properties: {authn, authz, ownership, validation, signing, replay, isolation, ...}
docs: {provided paths, missing, conflicts}
context_confidence: high|medium|low
```

```text
[DIFF_SCOPE]
mode: worktree|staged|unstaged|commit|commits|range|base_head|merge_base|patch|prs
repo_root: {absolute path}
base: {ref or n/a}
head: {ref or n/a}
commits: {list or n/a}
patches: {list or n/a}
changed_files: {count and representative list}
changed_hunks: {file:line ranges}
renames_deletes: {if any}
excluded: {path and reason}
```

```text
[FEATURE_SECURITY_PROFILE]
new_entrypoints: {...}
modified_controls: {...}
modified_sinks: {...}
modified_data_models: {...}
modified_file_network_ops: {...}
modified_crypto_config: {...}
dependency_ci_changes: {...}
risk_dimensions: {D1-D10 with reasons}
```

```text
[RELEVANT_SUPPORTING_FILES]
{path}: reason={caller|callee|auth_chain|route_registry|sanitizer|sink_helper|config_profile|dependency_context}
```

```text
[GRAPH_CONTEXT_PROFILE]
providers:
  codegraph: available|missing|not_indexed|error
  code-review-graph: available|missing|not_indexed|error
graph_confidence: none|low|medium|high
risk_score: {optional provider risk score}
changed_symbols: {name,file,line,provider}
impacted_files: {path,reason,provider}
affected_flows: {name,criticality,files}
test_gaps: {symbol,file,line}
supporting_files_added: {path,reason,provider}
limitations: {stale graph, missing graph, provider errors}
```

```text
[CONTEXT_GAPS]
{missing feature docs, unknown exposure, unresolved PR fetch, conflicting doc/code assumptions}
```

## Worklist And Coverage

必须使用确定性 worklist:

```text
audit_generate_diff_worklist(...)
```

该工具由 `.opencode/plugin/git-diff-harness.js` 独立暴露。若 OpenCode plugin tool 不可用，才 fallback 到:

```text
python3 references/core/git_diff_worklist.py ...
```

默认输出:

```text
{target_project}/audit-output/git-diff-scans/{scan_id}/artifacts/02_worklist/diff_worklist.csv
{target_project}/audit-output/git-diff-scans/{scan_id}/artifacts/02_worklist/deep_review_input.csv
{target_project}/audit-output/git-diff-scans/{scan_id}/artifacts/02_worklist/work_ledger.md
{target_project}/audit-output/git-diff-scans/{scan_id}/artifacts/06_graph_context/graph_context.json
{target_project}/audit-output/git-diff-scans/{scan_id}/artifacts/06_graph_context/graph_context.md
```

每个 source-like changed file 必须有覆盖结论:

| disposition | 含义 |
|-------------|------|
| `covered` | 完整审阅了 changed hunks 和必要上下文 |
| `not_applicable` | 非安全相关或非源码，但说明理由 |
| `suppressed` | 用户排除或 generated/vendor/test，说明证据 |
| `deferred` | 因缺少 PR/patch/docs/依赖或预算无法闭合，说明 blocker |

只有搜索命中或只看 hunk 不算 covered。必须记录功能语义、变更行为、安全属性和候选结论。

## Optional Graph Context

在 worklist 生成后、漏洞挖掘前，调度器应加载 `audit-graph-context` 并运行:

```text
audit_generate_graph_context(...)
```

该工具由 `.opencode/plugin/git-diff-harness.js` 独立暴露。若 OpenCode plugin tool 不可用，才 fallback 到:

```text
python3 references/core/graph_context_adapter.py ...
```

Graph context 的作用:
- 生成并驱动 `[GRAPH_REVIEW_QUEUE]`，改变漏洞挖掘的第一阅读顺序
- 扩展 `[RELEVANT_SUPPORTING_FILES]`
- 标注 changed symbols、affected flows、test gaps
- 辅助 `hybrid` 模式决定是否派专项 Agent
- 在报告中说明 blast radius 和图上下文局限

Graph context 的限制:
- 不安装、不自动构建索引
- provider 不可用时不得阻断审计
- graph risk score 不是安全严重度
- final finding 仍必须来自真实代码证据
- 不允许只把 graph context 写入报告；若 `graph_review_queue` 非空，必须先按队列读代码，再回到普通 diff 文件顺序

必须输出:

```text
[GRAPH_CONTEXT_PROFILE]
[GRAPH_REVIEW_QUEUE]
[GRAPH_SUPPORTING_FILES]
```

支持的 graph-derived supporting file reasons:

```text
graph_caller
graph_callee
graph_impact
graph_flow
graph_test_gap
graph_route
graph_priority
```

## Finding Rules

最终 finding 必须回答:

1. 属于哪个功能。
2. 功能文档或代码推断出的预期安全属性是什么。
3. 本次变更如何新增、削弱、绕过或重新暴露该属性。
4. 攻击者从哪个入口触发。
5. Source / broken control / sink 或配置/依赖证据在哪里。
6. 为什么这是该功能引入或影响的风险，而不是无关旧问题。

不得报告:
- 与本功能无关的历史漏洞，除非本次变更让它新可达或影响面变大
- 只有 sink 命中但无法绑定功能入口或 changed control 的问题
- 只由文档推断、没有真实代码证据的问题

## Agent Contract Additions

当 `engine=agents|hybrid` 时，注入给每个子 Agent:

```text
[FEATURE_PROFILE] 功能意图、角色、资产、入口、信任边界、预期安全属性
[DIFF_SCOPE] Git 范围、changed files、changed hunks
[FEATURE_DOC_CONTEXT] 已读取的功能文档摘要、冲突和缺口
[RELEVANT_SUPPORTING_FILES] 允许读取的 supporting files 和理由
[GRAPH_CONTEXT_PROFILE] 可选图上下文、provider 状态、impact/flow/test-gap 信号
[GRAPH_SUPPORTING_FILES] graph-derived supporting files，必须实际读取后才可作为证据
[INCREMENTAL_RULES]
  - deep-only
  - stay feature-scoped
  - final candidate must bind to changed line/hunk/control or diff-affected old sink
  - D1-D10 is coverage taxonomy, not exploration limit
```

子 Agent 输出中的 `CANDIDATE_LEDGER` 仍写入现有审计 DB；不得创建 per-agent JSONL 候选账本。

## Report Rules

最终报告使用 `references/core/git_diff_report_template.md`。报告必须保存到:

```text
{target_project}/audit-output/git-diff-scans/{scan_id}/report.md
```

报告必须包含:
- 功能画像
- 代码范围
- 文档上下文
- Reviewed Feature Surfaces
- Candidate 覆盖与 Known Gaps
- Final Findings
- No findings reason (若无漏洞)
