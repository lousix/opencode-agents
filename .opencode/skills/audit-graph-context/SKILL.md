---
name: audit-graph-context
description: "Optional graph-context enrichment for feature-centric incremental security review using CodeGraph or code-review-graph when available."
---

# Audit Graph Context Skill

> 可选图上下文层。用于把 Git 变更映射到调用方、被调方、影响半径、执行流和测试缺口，辅助功能增量安全审计选择 supporting files。

## Core Principle

```text
Graph helps choose where to look.
Graph does not prove a vulnerability.
No graph tool is required for audit completion.
```

图结果只能作为:
- 漏洞挖掘前的阅读顺序和导航队列
- supporting files 选择依据
- blast radius / affected flows 画像
- hybrid 模式下是否派专项 Agent 的信号
- final report 的 Reviewed Feature Surfaces 补充

图结果不能作为:
- 漏洞成立证据
- Source/Sink/Control 的唯一证据
- Critical/High 严重度依据
- worklist 覆盖完成依据

## Providers

支持两个可选 provider:

| Provider | Detection | Useful Signals |
|----------|-----------|----------------|
| `codegraph` | `codegraph` CLI + `.codegraph/` index | symbol search, callers, callees, impact, framework route context |
| `code-review-graph` | `code-review-graph` CLI + `.code-review-graph/` index | detect-changes JSON, risk score, affected flows, test gaps, review priorities |

MCP 工具若已由运行时暴露，也可以直接使用；否则通过本项目的 adapter 脚本调用 CLI。

## Pre-Audit Preparation

审计前若用户明确要求初始化或更新图数据库，使用:

```text
python3 references/core/init_graph_context.py --repo {repo_root} --mode update
```

该脚本只在目标项目下准备 `.codegraph/`、`.code-review-graph/`，并写入目标项目本地 `.git/info/exclude`。不要把图数据库放在审计框架目录下。

## Required Adapter

调度器必须优先调用:

```text
audit_generate_graph_context(
  repo_root={repo_root},
  worklist_path={scan_dir}/artifacts/02_worklist/deep_review_input.csv,
  scan_dir={scan_dir},
  base={base_or_HEAD}
)
```

该工具由 `.opencode/plugin/git-diff-harness.js` 独立暴露。若 OpenCode plugin tool 不可用，才 fallback 到:

```text
python3 references/core/graph_context_adapter.py ...
```

若 adapter 返回 `status=unavailable`，继续审计并在 `[CONTEXT_GAPS]` 记录 `graph_context_unavailable`。

## Graph-First Consumption Contract

如果 `graph_context.json` 中 `graph_review_queue` 非空，调度器必须先消费该队列，再按普通 `deep_review_input.csv` 文件顺序补齐覆盖。

必须执行:

1. 读取 `graph_context.json`，生成 `[GRAPH_REVIEW_QUEUE]`。
2. 按 `priority` 顺序审计队列项，至少覆盖所有 `review_priority`、`changed_symbol`、`caller_entrypoint`、`callee_or_sink`。
3. 对每个队列项读取真实代码文件；只读 graph metadata 不算覆盖。
4. 对 caller/callee 项执行 `caller -> changed/control -> callee/sink` 追踪，记录在 `work_ledger.md`。
5. 如果跳过队列项，必须在 `[CONTEXT_GAPS]` 写明原因。
6. 队列完成后，才回到普通 changed files，覆盖图数据未覆盖的文件、配置、Docker、文档和非代码资源。

严禁:

- 只把 Graph Context 写入报告而不改变阅读顺序。
- 用 diff 文件列表顺序覆盖掉 `graph_review_queue` 的优先级。
- 把 `supporting_files` 当作最终证据而不读源码。

## Output Block

调度器读取 adapter 输出后生成:

```text
[GRAPH_CONTEXT_PROFILE]
providers:
  codegraph: available|missing|not_indexed|error
  code-review-graph: available|missing|not_indexed|error
provider_selection:
  raw_changed_symbols_count
  selected_changed_symbols_count
  raw_edge_items_count
  selected_edge_items_count
  raw_components
  selected_components
  raw_categories
  selected_categories
  excluded_test_count
  excluded_build_artifact_count
  raw_test_symbol_ratio
  selected_test_symbol_ratio
raw_artifacts: {provider raw JSON paths}
graph_confidence: none|low|medium|high
risk_score: {provider score or n/a}
changed_symbols: {name,file,line,provider}
graph_first_required: true|false
graph_review_queue: {priority,kind,symbol,file,line,reason,review_action}
navigation_edges: {caller|callee|impact edges}
impacted_files: {path,reason,provider}
affected_flows: {name,criticality,files}
test_gaps: {symbol,file,line}
supporting_files_added: {path,reason,provider}
limitations: {...}
```

## Provider Quality Checks

不要只看 `provider.status=ok`。调度器必须检查 `providers[].selection`:

- 如果 raw components 多而 selected components 少，说明 adapter/provider 选择有偏斜，必须记录 limitation。
- 如果 `raw_test_symbol_ratio > 0.8` 且生产 changed symbols 很少，降低 `code-review-graph` 在安全审计中的权重。
- 如果 `code-review-graph` 只贡献 test gaps，不得让 test gaps 挤占 graph-first 队列。
- 即使 provider 整体降权，仍要保留并审阅生产 changed symbols，再交给 CodeGraph 追 caller/callee/impact。
- `selection_category=production` 和 `config_supply_chain` 是主审计输入。
- `selection_category=test_auxiliary` 只能作为辅助验证、集成场景或攻击路径复现上下文，不得挤占生产路径审计。
- `test_noisy` 和 `build_artifact` 默认不进入主队列；完整数据在 `raw_artifacts` 中保留。

## Supporting File Reasons

Graph-derived supporting files must use one of:

| reason | Meaning |
|--------|---------|
| `graph_caller` | Caller of a changed symbol |
| `graph_callee` | Callee from a changed symbol |
| `graph_impact` | File in impact radius |
| `graph_flow` | File participates in an affected execution flow |
| `graph_test_gap` | Test or missing-test signal for changed code |
| `graph_route` | Route/handler relation from graph |
| `graph_priority` | High-priority changed node from provider risk ranking |

Each graph supporting file must still be read before it can be cited as evidence.

## Agent Contract Additions

When `engine=agents|hybrid`, inject:

```text
[GRAPH_CONTEXT_PROFILE]
[GRAPH_REVIEW_QUEUE]
[GRAPH_SUPPORTING_FILES]
```

Subagents must use `[GRAPH_REVIEW_QUEUE]` as their first navigation input when it is non-empty. They may use graph files as prioritized context, but must not report findings from graph metadata alone.
