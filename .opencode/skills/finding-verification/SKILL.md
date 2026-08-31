---
name: finding-verification
description: "Pre-report finding verification contract. Re-checks whether each vulnerability has a real external Source, reachable Sink, bypassable or missing sanitization, and practical exploitability before final reporting."
---

# Finding Verification Skill

> 报告前真实性复核 — 逐个漏洞复查 Source、Sink、净化、可利用性，并按证据强度保留或降级。

## 触发条件

当 `audit-report` 对一个 `finding_id` 单独 dispatch `@audit-verification` 并要求 `[FINDING_DETAIL]`、`报告前复核` 时加载本 skill。漏洞挖掘 agent 不应执行常规报告前复核。

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
3. 沿 Source → Transform → Sanitizer → Sink 逐跳核验，每一跳必须有实际代码和相关函数名称。Source/Sink 至少保存 8 行非空上下文代码，关键中间节点至少 5 行。
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

复核完成后，`@audit-verification` 必须执行两步写库。第一步保存复核结论:

```
audit_save_verification(finding_id, verifier_agent, verdict,
                        source_status, sink_status, sanitizer_status,
                        exploitability, severity_action,
                        true_source?, key_gap?, exploit_method?, conclusion?)
```

第二步把复核阶段补充的事实写回最终 finding 和 sink chain:

```
audit_update_finding_after_verification(
  finding_id,
  severity?, confidence?, description?, attack_vector?, poc?,
  vuln_code?, file_path?, line_number?, cwe?, cvss_score?,
  sink_chain_steps?
)
```

写回规则:
- 若复核找到了更真实的 Source，必须用 `sink_chain_steps` 替换旧链路。
- `sink_chain_steps` 必须是非空 JSON 数组；每项优先使用固定字段：
  `{"step_type":"Source|Transform|Sanitizer|Sink","file_path":"...","line_number":42,"function_name":"Class.method","context_start_line":36,"context_end_line":49,"code_snippet":"多行上下文代码","notes":"..."}`
- 禁止传空数组、空对象或无位置/代码/说明的步骤。若工具返回 `error`、`saved=0` 或 `replaced_steps=0`，必须修正参数重试，不得继续生成最终报告。
- Critical/High/Medium 至少写回一个 Source 和一个 Sink；Source/Sink 必须有精确文件行号、相关函数名、上下文行范围和至少 8 行非空真实代码片段。
- 若复核补充了攻击者利用方法，必须写入 `attack_vector`。
- `findings.poc` 只允许保存原始载荷或发现阶段线索，不能作为“已执行”的证据，也不能直接以 `text` 代码块进入最终报告。完整源码、构建/运行命令、预期/实际结果和负向对照必须写入 `finding_report_details` 的结构化 PoC 字段并内嵌到单漏洞 Markdown。
- 若发生降级，必须更新 `severity` 和 `confidence`，不只写 `severity_action`。
- 若判定 `DROP` 或 `FALSE_POSITIVE`，至少将 `confidence` 更新为 `误报/已排除` 或将 `severity` 更新为 `Info`，避免最终报告继续按高危展示。

确认漏洞的单项报告必须依据更新后的 `findings`、`sink_chains`、`finding_verifications`、`finding_report_details` 四类最终数据库结果生成，并且只输出中文 Markdown。PoC 材料全部在该 Markdown 内展示，不生成独立 PoC 文件或目录。误报只保存 `REJECTED` 状态和中文排除原因，不生成单漏洞修复报告。

每个 finding 都必须建立独立 `finding_detail_run`；发生中断时必须从最新 `finding_detail_checkpoint` 继续，不得重新核验已经闭合的阶段。

报告统计、漏洞编号和详情分组必须使用 `severity_action` 后的报告等级；原始等级只作为属性保留。
