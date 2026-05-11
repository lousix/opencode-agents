---
name: report-template
description: "Structured security audit report template focused on exploit narrative, root cause, verified source-to-sink data flow, key code analysis, PoC, and minimal remediation notes."
---

# Report Template Skill

> 安全审计报告模板 — 强调真实 Source、数据流证据、攻击者利用方法、PoC，弱化修复内容。

## 报告总体架构

```
1. 执行摘要 ── 审计范围、关键发现统计、最高风险总结
2. 漏洞统计表 ── 按等级汇总: Critical×N, High×N, Medium×N, Low×N
3. 真实性复核摘要 ── 每个漏洞的 Source/Sink/利用性复核结论和降级动作
4. 漏洞详情 ── Critical → High → Medium → Low
5. 攻击链分析 ── 多漏洞串联的端到端攻击路径
6. 正面发现 ── 项目做得好的安全实践
```

**每个漏洞条目必须包含**: 项目标签+编号与标题(如【项目名称】【H-01】远程命令执行) | 属性表(严重程度/CVSS/CWE/置信度/复核结论) | 漏洞描述 | 漏洞根因 | 攻击者利用方法 | 数据流总览 | 漏洞数据流分析/关键代码分析 | PoC | 简短修复提示

## 报告质量标准

| 标准 | 要求 |
|------|------|
| **可定位** | 每个漏洞有精确的文件路径和行号 |
| **可复现** | 提供足够信息让开发者复现问题 |
| **真实 Source** | Critical/High 必须证明攻击者可控 Source |
| **无误报** | 每个漏洞都经过报告前真实性复核 |
| **完整分析** | 不仅说"有问题"，还说明完整利用路径、根因、Source→Sink 代码证据 |
| **少修复** | 修复内容只保留最短方向，不展开大段修复代码 |

## 漏洞报告模板

````markdown
## 【项目名称】【H-01】漏洞标题

| 属性 | 值 |
|------|----|
| 漏洞名称 | 漏洞标题 |
| 严重程度 | High |
| CWE | CWE-89 |
| 置信度 | 高置信 |
| 复核结论 | VERIFIED / TRUE_SOURCE / KEEP |
| 位置 | `path/to/file.py:42` |

### 一、漏洞描述
描述漏洞性质、影响资产、攻击前置条件。

### 二、漏洞根因
说明真实 Source、传播过程、缺失或可绕过的安全控制、最终 Sink。

### 三、攻击者利用方法
从攻击者视角说明如何构造输入、触发链路并获得影响。

### 四、数据流总览

```text
Source: HTTP Request parameter
  -> Controller.method()
  -> Service.transform()
  -> Mapper/Sink.execute()
```

| 阶段 | 位置 | 变量 | 处理 | 安全判断 |
|------|------|------|------|----------|
| Source | `Controller.java:42` | `keyword` | 从请求读取 | TRUE_SOURCE |
| Transform | `Service.java:88` | `condition` | 字符串拼接 | 未净化 |
| Sink | `Mapper.java:57` | `sql` | 执行 SQL | 可注入 |

### 五、漏洞数据流分析 / 关键代码分析

#### 1. Source: 用户输入进入系统
位置: `Controller.java:42`

```java
// 8-15 行上下文，Critical/High 必须展示真实 Source
```

判断: 参数来自 HTTP 请求，攻击者可控。

#### 2. Transform: 输入被传播或拼接
位置: `Service.java:88`

```java
// 5-10 行上下文
```

判断: 未参数化、未白名单或净化可绕过。

#### 3. Sink: 危险函数被触发
位置: `Mapper.java:57`

```java
// 8-15 行上下文，展示危险函数或危险配置
```

判断: 数据到达 Sink 后造成 SQL 注入/RCE/文件读写/SSRF 等影响。

### 六、PoC
具体的利用步骤或payload

### 七、修复提示
1-3 条短建议即可，不输出大段修复代码。

### 八、参考
- CWE-XXX
````

## 污点分析报告模板

> 完整模板: `references/core/taint_analysis.md`
> 格式: 基本信息(类型/CWE) → Source(位置/类型/代码) → Propagation(逐步路径) → Sink(位置/危害) → 根因 → 利用方法 → PoC

## 置信度标注

```
- [已验证]  ①完整数据流 ②无有效防护 ③可构造输入
- [高置信]  满足 ①+②，缺③
- [中置信]  仅满足①
- [需验证]  仅Grep命中

Critical/High: 必须 [高置信] 或 [已验证]
Medium: 允许 [中置信]
Low/Info: 允许 [需验证]
```

## Sink 覆盖与 Known Gaps

报告必须包含 D1/D4/D5/D6 的 sink-driven 覆盖摘要:
- `candidates / triaged / unchecked / high_path`
- 若存在 OPEN/TIMEOUT，必须列出文件、行号、sink_type、未完成原因；不得宣称该维度 100% 覆盖
- 若完整账本写入 `LEDGER_FILE`，报告应给出路径和 sha256

## 报告前复核要求

- Critical/High 必须展示 `TRUE_SOURCE`，否则降级。
- 只有 Sink 没有 Source 的发现，最多 Low/Info。
- Source、Sink、关键 Transform 均必须来自实际 Read 过的代码。
- 复核结果必须进入属性表或真实性复核摘要。
- 最终报告的统计、编号和分组使用复核后的报告等级；若发生降级，属性表保留原始等级。
