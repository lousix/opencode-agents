---
name: audit-harness
description: "OpenCode-native audit harness protocol for target-project context negotiation, mixed-language profiling, extension skill activation, and stable HARNESS_PROFILE injection."
---

# Audit Harness Skill

> OpenCode 原生 Harness 协议。核心目标: 让特殊语言组合、内部框架、业务暴露面和新漏洞规则通过独立 Skill 扩展接入，而不是修改通用 agent/checklist/reference。

## Core Principle

```
零配置可运行；上下文越多，审计越准；AI 先自主 Recon，再向用户补问。

用户上下文用于激活扩展、理解暴露面和校准严重度。
漏洞成立证据仍必须来自实际 Read 过的代码。
```

---

## Target Project Context

被审计目标项目可以维护自己的上下文文件:

```
{target_project}/audit-context.md
```

该文件属于目标项目，不属于本审计框架。若存在，Recon 阶段必须读取并合并；若不存在，不阻断审计。

### audit-context.md 推荐结构

```markdown
# Audit Context

## Languages
- Java: backend/**
- JavaScript: frontend/**

## Tech Stack
- Spring Boot
- MyBatis
- Vue
- Internal framework: Jalor

## Exposure
- /openapi/**: public internet
- /admin/**: internal employee network
- /job/**: scheduler only, no direct HTTP exposure

## Internal Framework
- @JalorOperation 表示接口操作权限声明
- 非 GET 接口必须有 @ServiceAudit
- @ServiceAudit.message 中参数必须匹配方法签名

## Auth
- public API 经过 API Gateway JWT 校验
- admin 使用 SSO + RBAC

## Focus
- D3 authorization
- D9 business logic
- D5 file operation
```

---

## Context Negotiation Protocol

Recon 阶段按以下顺序执行:

1. 自主识别项目事实: 语言比例、构建系统、框架、入口点、部署文件、认证链、可疑内部框架信号。
2. 若目标项目存在 `audit-context.md`，读取并提取语言、技术栈、暴露面、内部框架语义、角色/认证模型、排除目录。
3. 合并用户消息中的显式上下文、`audit-context.md` 和代码 Recon 结果。
4. 生成 `[HARNESS_PROFILE]`。
5. 激活扩展 Skill:
   - 不要在目标项目的 `.opencode/skills` 下 Glob；目标项目只提供 `audit-context.md`。
   - 先根据代码信号、用户输入、`audit-context.md` 和扩展 `Aliases` 归一化得到候选扩展名，例如 `Jalor框架` → `audit-ext-jalor`。
   - 对候选扩展优先调用 `skill({ name: "{extension}" })`；失败时才尝试读取审计框架自身的 `.opencode/skills/{extension}/SKILL.md`。
   - 只有在确认当前工作区存在审计框架 `.opencode/skills` 目录时，才可枚举 `audit-ext-*` / `audit-vuln-*`；目录不存在时记录 `extension_discovery=skipped(no_framework_skill_dir)`，不得把它当作错误。
6. 生成 `[ACTIVE_EXTENSIONS]` 和 `[CONTEXT_GAPS]`。
7. 仅当缺失信息会影响暴露面、严重度、Agent 分配或内部框架语义时，才向用户追问。

### Conflict Rule

| 信息类型 | 优先级 |
|----------|--------|
| 文件存在、代码片段、行号、调用链 | 代码证据最高 |
| 生产暴露面、网关策略、部署角色 | `audit-context.md` / 用户说明优先，代码辅助验证 |
| 内部框架语义 | `audit-context.md` / 用户说明优先，代码使用证据辅助 |
| 漏洞成立证据 | 必须来自真实代码 |
| 严重度 | 代码证据 + 暴露面上下文共同决定 |

用户上下文和代码事实冲突时，必须在 `[CONTEXT_GAPS]` 或 `[RECON]` 中标注，不得静默覆盖。

---

## HARNESS_PROFILE Output

Recon 后必须输出:

```text
[HARNESS_PROFILE]
target_context: {found|missing}:{path}
languages:
  {Language}: {paths}, {percent}
frameworks:
  {framework/version/list}
project_type:
  {SaaS | internal_admin | data_platform | identity | CMS | IoT | mixed | unknown}
exposure:
  public: {paths/routes or unknown}
  internal: {paths/routes or unknown}
  scheduler: {paths/routes or unknown}
trust_boundaries:
  {internet -> gateway -> app -> db | internal employee -> admin | ...}
active_extensions:
  {extension names}
context_confidence:
  high|medium|low
```

```text
[ACTIVE_EXTENSIONS]
- {skill_name}: {matched_by: code_pattern|dependency|audit-context|user_input}, agents={...}, dimensions={...}
```

```text
[CONTEXT_GAPS]
1. {缺失信息} | impact={exposure|severity|agent-split|internal-semantics} | ask_user={yes|no}
```

---

## Extension Skill Naming

扩展 Skill 使用 OpenCode 原生 skill 目录:

```
.opencode/skills/audit-ext-{name}/SKILL.md   # 内部框架、业务场景、架构暴露面
.opencode/skills/audit-vuln-{name}/SKILL.md  # 新漏洞类型、新利用方式、版本边界
```

不要把特殊场景规则直接写入通用 agent、通用 checklist 或通用 language reference。
不要要求目标项目创建 `.opencode/skills` 目录；目标项目侧的人工输入只放 `audit-context.md`。

---

## Extension Alias Resolution

用户输入、`audit-context.md` 和技术栈名称只作为 hint，不要求与 Skill 名完全一致。

匹配规则:
1. 先匹配稳定 Skill 名: `audit-ext-{name}` / `audit-vuln-{name}`
2. 再匹配扩展 Skill 的 `Aliases`
3. 再匹配扩展 Skill 的 `Activation Signals`
4. 大小写、空格、连字符、下划线、中英文连接词和常见后缀（framework/框架/平台）可做轻量归一化

若仍无法匹配，不得失败；继续按通用技术栈审计，并在 `[CONTEXT_GAPS]` 中记录未识别的技术栈或内部框架名称。

---

## Extension Skill Template

```markdown
---
name: audit-ext-example
description: "Internal framework or scenario audit extension."
---

# Audit Extension: Example

## Extension Metadata

type: framework | scenario | internal | vulnerability
languages: Java, JavaScript
dimensions: D2, D3, D9
agents: audit-recon, audit-d2d3d9-control, audit-report, audit-verification
priority: 80

## Aliases

- example framework
- example internal platform
- Example框架

## Activation Signals

- 代码中出现某些注解、类名、配置项
- 依赖文件中出现某些包
- 用户或 target `audit-context.md` 明确说明

## Load References

激活后读取:
- references/extensions/example.md

## Recon Additions

Recon 阶段额外统计什么。

## Agent Contract Additions

给哪些子 Agent 增加哪些检查规则。

## Finding Rules

缺失或错误时如何定级、对应 CWE。

## Verification Rules

报告前复核时必须重新读取哪些代码证据。
```

---

## Agent Injection Rule

Dispatcher 在启动每个子 Agent 前，必须把以下内容注入 Agent Contract:

```
[HARNESS_PROFILE]   Recon 产出的最终 profile
[ACTIVE_EXTENSIONS] 激活的扩展 Skill 列表及触发原因
[CONTEXT_GAPS]      未解决但可能影响结论的上下文缺口
```

子 Agent 必须加载与自己 `agents` / `dimensions` 匹配的 active extension Skill，并执行其 `Agent Contract Additions`。
