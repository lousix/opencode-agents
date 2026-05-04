# Jalor Framework Security Reference

> Jalor 内部 Spring Web 框架专项参考。执行入口见 `.opencode/skills/audit-ext-jalor/SKILL.md`。

## 框架语义

Jalor 项目中常见两个接口治理注解:

- `@JalorOperation`: 接口级操作权限声明，用于描述或绑定操作权限。
- `@ServiceAudit`: 服务审计日志声明，用于记录非 GET 修改类操作的审计上下文。

这些注解是否直接完成鉴权取决于项目内部实现。审计时不能只看注解名称，需要读取相关 AOP、Interceptor、Filter 或注解处理器确认其真实效果。

## 主要风险

### 1. 接口缺少操作权限声明

风险模式:

```java
@PostMapping("/user/delete")
public Result deleteUser(@RequestParam Long id) {
    return userService.delete(id);
}
```

若项目约定每个映射接口都必须声明 `@JalorOperation`，缺失会导致权限治理、菜单/操作映射或审计闭环失效。

判定:

- 缺少 `@JalorOperation` 且没有等价控制证据: High / CWE-862
- 存在统一类级控制或 AOP 等价控制: 需读取实现后降级或排除

### 2. 非 GET 修改接口缺少服务审计

风险模式:

```java
@DeleteMapping("/file/{id}")
@JalorOperation("file.delete")
public Result deleteFile(@PathVariable Long id) {
    return fileService.delete(id);
}
```

修改类操作缺少 `@ServiceAudit` 会影响追责、告警、合规审计和攻击溯源。

判定:

- 非 GET 缺少 `@ServiceAudit`: Medium / CWE-778
- 只读 GET 接口通常不强制要求，但如果 GET 执行状态修改，应按修改类处理

### 3. 审计 message 参数不匹配

风险模式:

```java
@PostMapping("/role/update")
@JalorOperation("role.update")
@ServiceAudit(message = "update role {roleId}")
public Result updateRole(@RequestBody RoleUpdateDTO dto) {
    return roleService.update(dto);
}
```

`message` 引用了 `{roleId}`，但方法签名中没有 `roleId` 参数。若系统依赖 message 参数提取审计对象，会导致日志无法关联真实资源。

支持的占位形式:

- `{id}`
- `${id}`
- `#{id}`
- `dto.id`

`dto.id` 至少要求根参数 `dto` 存在；若需要精确验证，应继续读取 DTO 字段。

判定:

- message 为空: Medium / CWE-778
- message 参数无法匹配方法签名: Medium / CWE-778

## 审计步骤

1. 枚举 Controller 映射方法。
2. 记录 HTTP method，`@RequestMapping` 未指定 method 时按可能包含非 GET 处理。
3. 检查 `@JalorOperation` 是否存在。
4. 对非 GET 检查 `@ServiceAudit` 是否存在。
5. 解析 `@ServiceAudit.message`。
6. 提取 message 参数占位符并与方法签名参数名比对。
7. 若存在类级注解、组合注解、AOP 或统一拦截器，读取真实实现后复核。

## Grep 思路

实际执行时应使用 OpenCode Grep/Glob/Read 工具，不要机械照抄 shell 命令。

```text
@JalorOperation
@ServiceAudit
@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping|@RequestMapping
ServiceAudit\(.*message
```

## 报告证据要求

每个 finding 至少包含:

- Controller 文件和行号
- 映射注解代码
- `@JalorOperation` / `@ServiceAudit` 缺失或错误的直接证据
- 方法签名
- 若涉及 message 参数不匹配，展示 message 和方法参数列表

报告前复核必须重新 Read 这些代码，不能仅依赖 Recon 统计。

