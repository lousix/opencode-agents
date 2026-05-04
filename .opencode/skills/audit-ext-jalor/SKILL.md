---
name: audit-ext-jalor
description: "Jalor internal Spring framework audit extension for endpoint operation authorization and service audit logging coverage."
---

# Audit Extension: Jalor

> Jalor 内部框架专项扩展。该 Skill 是特殊场景入口；详细背景和案例见 `references/extensions/jalor.md`。

## Extension Metadata

```
type: framework, internal
languages: Java
dimensions: D2, D3, D9
agents: audit-recon, audit-d2d3d9-control, audit-evaluation, audit-report, audit-verification
priority: 90
```

---

## Aliases

- Jalor
- jalor-framework
- jalor spring
- Jalor框架
- Jalor平台
- 公司内部 Jalor 框架
- `@JalorOperation`
- `@ServiceAudit`

---

## Activation Signals

满足任一条件即可激活:

- 代码中出现 `@JalorOperation`
- 代码中出现 `@ServiceAudit`
- 用户消息或目标项目 `audit-context.md` 明确说明使用 Jalor
- 包名、依赖名、配置名中出现 `jalor`

激活后必须读取:

- `references/extensions/jalor.md`

---

## Internal Knowledge

- `@JalorOperation` 表示接口级操作权限声明。
- `@ServiceAudit` 表示服务审计日志声明。
- 所有映射接口都应声明 `@JalorOperation`。
- 所有非 GET 修改类接口都应声明 `@ServiceAudit`。
- `@ServiceAudit.message` 不应为空，且其中引用的参数必须能在方法签名中找到。

用户或 `audit-context.md` 可补充本项目对 Jalor 注解的内部语义；但漏洞证据仍必须来自实际 Controller 代码。

---

## Recon Additions

`audit-recon` 激活本扩展后，必须在端点-权限矩阵或扩展字段中额外记录:

| 字段 | 含义 |
|------|------|
| `jalor_operation_present` | 端点方法是否存在 `@JalorOperation` |
| `service_audit_present` | 端点方法是否存在 `@ServiceAudit` |
| `service_audit_message` | `@ServiceAudit.message` 原始值 |
| `message_placeholders` | message 中的 `{id}` / `${id}` / `#{id}` / `dto.id` 等引用 |
| `method_params` | 方法签名中的参数名 |
| `message_params_valid` | message 引用是否能匹配方法参数 |

Recon 输出中的 `端点-权限矩阵` 必须包含 Jalor 覆盖统计:

```text
Jalor: endpoints={N}, JalorOperation={covered/total}, non_get_ServiceAudit={covered/total}, message_params_valid={valid/checked}
```

---

## Agent Contract Additions

注入给 `audit-d2d3d9-control`:

1. 枚举所有带 `@GetMapping/@PostMapping/@PutMapping/@DeleteMapping/@PatchMapping/@RequestMapping` 的 Controller 方法。
2. 每个映射接口必须存在 `@JalorOperation()`。
3. 所有非 GET 接口必须存在 `@ServiceAudit`。
4. `@RequestMapping` 未显式限定 HTTP method 时，按可能包含非 GET 处理，要求检查 `@ServiceAudit`。
5. `@ServiceAudit.message` 必须存在且非空。
6. message 中的参数占位符必须与方法签名参数名一致。
7. 支持的占位形式:
   - `{id}`
   - `${id}`
   - `#{id}`
   - `dto.id` 形式至少要求根参数 `dto` 在方法签名中真实存在。

---

## Finding Rules

| 条件 | 严重度 | CWE | 说明 |
|------|--------|-----|------|
| 映射接口缺少 `@JalorOperation` | High | CWE-862 | 接口级操作权限声明缺失 |
| 非 GET 接口缺少 `@ServiceAudit` | Medium | CWE-778 | 敏感修改操作审计日志缺失 |
| `@ServiceAudit.message` 为空 | Medium | CWE-778 | 审计日志不可追踪 |
| message 引用参数与方法签名不匹配 | Medium | CWE-778 | 审计日志记录错误对象或不可解析对象 |

若 `audit-context.md` 说明某些端点由网关、父类、AOP 或统一拦截器补充了等价控制，必须 Read 相关实现后再决定是否降级或排除。

---

## Verification Rules

报告前真实性复核必须重新读取:

1. 原始 Controller 方法所在文件和行号。
2. 方法级和类级注解。
3. 方法签名参数名。
4. `@ServiceAudit.message` 原始字符串。
5. 如声称存在等价控制，必须读取对应 Filter/AOP/Interceptor/父类实现。

不得仅根据 Recon 统计或用户上下文保留 finding。
