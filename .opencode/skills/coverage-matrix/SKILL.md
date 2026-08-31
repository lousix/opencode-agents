---
name: coverage-matrix
description: "Two-layer checklist architecture with D1-D10 security coverage matrix and language-specific semantic prompts for gap verification after free audit."
---

# Two-Layer Checklist Architecture (两层检查清单架构)

> **核心原则**: Checklist 不驱动审计，而是验证覆盖。LLM 先自由审计(Phase 2A)，再用矩阵查漏(Phase 2B)。

## Layer 1: 覆盖率矩阵 (Phase 2B 加载)

**加载时机**: Phase 2A（LLM自由审计）完成后
**作用**: 对照 10 个安全维度 (D1-D10)，标记已覆盖/未覆盖

| # | 维度 | 关键问题 | 已覆盖? | 发现数 |
|---|------|---------|---------|--------|
| D1 | 注入 | 用户输入是否能到达 SQL/Cmd/LDAP/SSTI/SpEL 执行点？ | [ ] | |
| D2 | 认证 | Token/Session 生成、验证、过期是否完整？密钥是否安全？ | [ ] | |
| D3 | 授权 | 每个敏感操作是否验证用户归属？CRUD 权限是否一致？ | [ ] | |
| D4 | Unsafe Runtime/内存安全 | 是否存在不可信反序列化、Gadget、越界/UAF/Unsafe/FFI 生命周期风险？ | [ ] | |
| D5 | 文件操作 | 上传/下载/读取路径是否可控？是否有路径遍历？ | [ ] | |
| D6 | SSRF | 服务端 HTTP 请求的 URL 是否用户可控？协议是否限制？ | [ ] | |
| D7 | 加密 | 硬编码密钥/IV？ECB/CBC-no-MAC？弱KDF？RSA-PKCS1v1.5？证书校验绕过？ | [ ] | |
| D8 | 配置 | 调试接口(Actuator/pprof)是否暴露？CORS 是否过宽？错误堆栈是否泄露？ | [ ] | |
| D9 | 业务逻辑 | 竞态条件？支付金额可篡改？流程可跳过？Mass Assignment？状态/配额/幂等不变量是否完整？ | [ ] | |
| D10 | 供应链 | 依赖是否有已知 CVE？版本是否在安全范围？ | [ ] | |

### 使用规则

- **未覆盖维度** → 加载 `references/checklists/{language}.md` 中对应 `## D{N}` 段落的语义提示，补充审计
- D1-D10 十个独立 Agent 默认全部启动；风险权重只影响先后和深度
- 无适用攻击面必须由对应 Agent 保存 `NOT_APPLICABLE + reason + checkpoint`，不得静默跳过

---

## Layer 2: 语义提示 (按需加载未覆盖维度)

| 主语言 | 语义提示文件 |
|--------|-------------|
| Java | `references/checklists/java.md` |
| Python | `references/checklists/python.md` |
| PHP | `references/checklists/php.md` |
| JavaScript/Node.js | `references/checklists/javascript.md` |
| Go | `references/checklists/go.md` |
| .NET/C# | `references/checklists/dotnet.md` |
| Ruby | `references/checklists/ruby.md` |
| C/C++ | `references/checklists/c_cpp.md` |
| Rust | `references/checklists/rust.md` |

通用维度: `references/checklists/universal.md` (架构/逻辑级)

---

## 加载指令

1. **Phase 2A 期间禁止加载 checklist**。LLM 使用自身安全知识自由审计。
2. Phase 2A 完成后，加载 `coverage_matrix.md`，标记已覆盖维度。
3. 对未覆盖维度，加载 `{language}.md` 中对应 `## D{N}` 段落（按需加载，非全量）。
4. 语义提示仅提供关键问题和判定规则，LLM 自行决定搜索策略。

**依赖感知裁剪**: 读取 pom.xml/package.json/go.mod 后，D10(供应链)维度中不存在的依赖标记SKIP。

---

## 覆盖标准（按审计策略分轨）

### Sink-driven 维度 (D1/D4反序列化/D5/D6)
- ✅已覆盖 = 核心 Sink 类别均被搜索 + `CANDIDATE_LEDGER(candidate_kind=SINK)` 完整 + `candidate_triage=100%` + `unchecked=0` + Critical/High 候选 `high_path=100%`
- ⚠️浅覆盖 = 搜索过但 Sink 类别有遗漏 / 仅 Grep 未追踪 / 缺少 SINK candidates / `candidate_triage<100%` / `unchecked>0` / Critical/High Sink 链不完整
- ❌未覆盖 = 未被任何 Agent 搜索

### Control-driven 维度 (D2认证缺失/D3/D9)
- D2 ✅已覆盖 = 登录/Token/Session/匿名入口与认证链已验证 + CONTROL/CONFIG ledger 完整 + `unchecked=0`
- D3 ✅已覆盖 = 端点审计率 ≥ 50%(deep)/30%(standard) + ≥3种资源类型 CRUD/ownership/tenant 对比 + IDOR覆盖 + CONTROL ledger 完整 + `unchecked=0`
- D9 ✅已覆盖 = 关键业务操作/状态/数值/并发不变量已枚举 + CONTROL ledger 完整 + `unchecked=0`
- ⚠️浅覆盖 = 仅 Grep pattern 未系统枚举 / 缺少 CONTROL candidates / `unchecked>0`
- ❌未覆盖 = 未执行 Control-driven 审计

**Harness 扩展覆盖追加**:
- 若 `[ACTIVE_EXTENSIONS]` 中存在覆盖 D3/D9 的扩展 Skill，D3/D9 覆盖判定必须追加该扩展的 Coverage / Agent Contract requirements
- 未执行 active extension required checks 时，即使已做一般性 CRUD/IDOR 对比，也只能标记为 ⚠️浅覆盖
- 扩展覆盖状态必须写入 Agent HEADER 的 `ACTIVE_EXTENSIONS`
- 扩展规则产生的候选必须进入通用 `CANDIDATE_LEDGER`，使用扩展自身的 `rule_id`，不得只输出百分比

### Config-driven 维度 (D2/D7/D8/D10)
- ✅已覆盖 = 核心配置项均已检查 + 版本/算法已对比基线 + `CANDIDATE_LEDGER(candidate_kind=CONFIG)` 完整 + `unchecked=0`
- ⚠️浅覆盖 = 仅检查了部分配置 / 缺少 CONFIG candidates / `unchecked>0`
- ❌未覆盖 = 未检查

### Memory-driven 维度 (D4)
- ✅已覆盖 = 已枚举适用的 allocation/bounds/ownership/free/use 与 Unsafe/FFI 类别 + `CANDIDATE_LEDGER(candidate_kind=MEMORY)` 完整 + `unchecked=0`
- ⚠️浅覆盖 = 只搜索危险 API、未验证生命周期/边界/可达性，或存在 MEMORY OPEN/TIMEOUT
- N/A = D4 Agent 启动后确认无反序列化、native、unsafe、FFI 攻击面，并将证据写入 agent run/checkpoint

### T3 Sink 覆盖验证
对每个标记 ✅ 的维度，优先检查 `audit_get_candidate_coverage` / `audit_get_unchecked_candidates`。如类别遗漏、候选未入库或仍有 OPEN/TIMEOUT → 降级 ⚠️。

### 强制覆盖
D1(注入) + D2(认证) + D3(授权) 必须覆盖，否则不可进入 REPORT。

### Agent Run 完整性
- 每轮必须通过 `audit_list_agent_runs` 得到 D1-D10 十条独立记录。
- `QUEUED/RUNNING/RESUMING/INTERRUPTED` 均阻断轮次结束；`NOT_APPLICABLE` 必须有 `status_reason/skip_code` 和适用性 checkpoint。
- 调度失败、用户排除或注册缺失必须显示原因，禁止把“没有结果”当作已覆盖。
