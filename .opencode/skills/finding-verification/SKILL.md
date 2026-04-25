---
name: finding-verification
description: "Pre-report finding verification contract. Re-checks whether each vulnerability has a real external Source, reachable Sink, bypassable or missing sanitization, and practical exploitability before final reporting."
---

# Finding Verification Skill

> 报告前真实性复核 — 逐个漏洞复查 Source、Sink、净化、可利用性，并按证据强度保留或降级。

## 触发条件

当调度器或 `audit-report` 要求 `[VERIFY_FINDING]`、`verification-only`、`报告前复核` 时加载本 skill。

## 复核目标

对已发现漏洞做真实性审查，不寻找新的漏洞，不扩展新的攻击面。每个 finding 必须回答：

1. 是否存在真实外部 Source？
2. Source 是否能到达报告中的 Sink？
3. 中间链路是否有净化、参数化、权限校验或路径限制？
4. 攻击者是否有实际可行的利用方法？
5. 原始严重等级是否应该保持、降级或删除？

## Source 真实性分级

| 等级 | 判定 | 示例 | 报告影响 |
|------|------|------|----------|
| TRUE_SOURCE | 真实攻击者可控输入 | HTTP 参数/Header/Cookie/Body、上传文件、MQ/RPC/Webhook 入站、OAuth/OIDC 回调、低权限用户可写数据库字段 | 可支撑 Critical/High |
| CONDITIONAL_SOURCE | 条件可控输入 | 管理员可编辑配置、部署 Profile、内部 API、需高权限写入的数据 | 通常降 1 级 |
| PSEUDO_SOURCE | 弱 Source 或假 Source | 常量、测试样例、启动参数、只读配置、不可被攻击者控制的内部变量 | 通常降到 Low/Info |
| NO_SOURCE | 未找到 Source | 只有 Sink 命中，无入口和调用链 | 删除或标记误报 |

## 复核操作

1. Read 原始 finding 中的文件和行号，确认代码仍存在。
2. Read Source 节点代码，确认输入来自真实外部边界。
3. 沿 Source → Transform → Sanitizer → Sink 逐跳核验，每一跳必须有实际代码。
4. 检查净化点是否有效：参数化、白名单、路径规范化、协议限制、权限校验、签名验证等。
5. 给出攻击者视角的最小利用路径。若无法说明利用路径，不得保持 Critical/High。

## 降级规则

| 条件 | severity_action |
|------|-----------------|
| TRUE_SOURCE + Sink 可达 + 无有效净化 + 可描述利用方法 | KEEP |
| TRUE_SOURCE + Sink 可达，但中间链路缺 1 个关键节点 | DOWNGRADE_1 |
| CONDITIONAL_SOURCE + Sink 可达 | DOWNGRADE_1 |
| PSEUDO_SOURCE 或仅 Sink 命中 | DOWNGRADE_2 |
| NO_SOURCE、Sink 不存在、文件/行号不真实、有效净化不可绕过 | DROP |

## 输出格式

```
[VERIFY]
finding_id: {id}
verdict: VERIFIED | PARTIAL | SINK_ONLY | FALSE_POSITIVE
source_status: TRUE_SOURCE | CONDITIONAL_SOURCE | PSEUDO_SOURCE | NO_SOURCE
sink_status: CONFIRMED | UNCLEAR | NOT_FOUND
sanitizer_status: NONE | BYPASSABLE | EFFECTIVE | UNKNOWN
exploitability: PRACTICAL | CONDITIONAL | THEORETICAL | NOT_EXPLOITABLE
severity_action: KEEP | DOWNGRADE_1 | DOWNGRADE_2 | DROP
真实Source: {file}:{line} {为什么攻击者可控}
关键断点: {若链路缺失，说明缺哪一跳}
利用方法: {攻击者如何触发 Source 到 Sink}
结论: {保留/降级/删除的理由}
```

Critical/High finding 必须达到 `VERIFIED` 或 `PARTIAL + TRUE_SOURCE`，否则最终报告必须降级。

## 落库要求

复核完成后，调度器或 `audit-report` 必须调用:

```
audit_save_verification(finding_id, verifier_agent, verdict,
                        source_status, sink_status, sanitizer_status,
                        exploitability, severity_action,
                        true_source?, key_gap?, exploit_method?, conclusion?)
```

最终 Markdown/HTML 报告优先使用 `finding_verifications` 表中的复核结果；没有复核结果时只能根据 Sink 链做弱推断，并应标记为需复核。

报告统计、漏洞编号和详情分组必须使用 `severity_action` 后的报告等级；原始等级只作为属性保留。
