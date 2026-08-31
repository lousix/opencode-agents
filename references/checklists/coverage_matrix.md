# Security Coverage Matrix (审后自检)

> Phase 2A（LLM 自由审计）完成后，对照此矩阵验证维度覆盖。
> 未覆盖维度需加载 `{language}.md` 中对应维度的语义提示并补充审计。

| # | 维度 | 关键问题 | 已覆盖? | 发现数 |
|---|------|---------|---------|--------|
| D1 | 注入 | 用户输入是否能到达 SQL/Cmd/LDAP/SSTI/SpEL 执行点？ | [ ] | |
| D2 | 认证 | Token/Session 生成、验证、过期是否完整？密钥是否安全？ | [ ] | |
| D3 | 授权 | 每个敏感操作是否验证用户归属？CRUD 权限是否一致？ | [ ] | |
| D4 | Unsafe Runtime / 内存安全 | 不可信反序列化/Gadget 是否可达？是否存在越界、UAF、错误分配、Unsafe/FFI 生命周期风险？ | [ ] | |
| D5 | 文件操作 | 上传/下载/读取路径是否可控？是否有路径遍历？ | [ ] | |
| D6 | SSRF | 服务端 HTTP 请求的 URL 是否用户可控？协议是否限制？ | [ ] | |
| D7 | 加密 | 硬编码密钥/IV？ECB/CBC-no-MAC？弱KDF？RSA-PKCS1v1.5？证书校验绕过？ | [ ] | |
| D8 | 配置 | 调试接口(Actuator/pprof)是否暴露？CORS 是否过宽？错误堆栈是否泄露？ | [ ] | |
| D9 | 业务逻辑 | 竞态条件？金额/库存可篡改？流程可跳过？Mass Assignment？幂等、配额和状态不变量是否完整？ | [ ] | |
| D10 | 供应链 | 依赖是否有已知 CVE？版本是否在安全范围？ | [ ] | |

## 使用规则

- **未覆盖维度** → 加载 `references/checklists/{language}.md` 中对应 `## D{N}` 段落的语义提示，补充审计
- D1-D10 十个独立 Agent 默认全部启动；权重只影响顺序和深度，不影响是否启动
- 无适用攻击面必须由对应 Agent 写入 `NOT_APPLICABLE + reason + checkpoint`，不得以“低优先级”静默跳过

## 覆盖标准（按审计策略分轨）

覆盖判定因维度类型而异，不同审计策略有不同标准：

### Sink-driven 维度 (D1, D4 反序列化, D5, D6)
- **已覆盖** = 核心 Sink 类别均被搜索 + `CANDIDATE_LEDGER(candidate_kind=SINK)` 完整 + `candidate_triage=100%` + `unchecked=0` + Critical/High 候选 `high_path=100%`
- **浅覆盖** = 搜索过但 Sink 类别有遗漏 / 仅 Grep 未追踪 / 缺少 SINK candidates / `candidate_triage<100%` / `unchecked>0` / Critical/High Sink 链不完整
- **未覆盖** = 该维度未被任何 Agent 搜索
- 中间候选账本不得写入文件；覆盖判定以 `audit_get_candidate_coverage` / `audit_get_unchecked_candidates` 或 Agent `CANDIDATE_LEDGER` 摘要为准

### Control-driven 维度 (D2, D3, D9)
- **D2 已覆盖** = 登录/Token/Session/匿名入口和认证链已验证 + CONTROL/CONFIG candidates 完整 + `unchecked=0`
- **D3 已覆盖** = 端点审计率 ≥ 50%(deep) / ≥ 30%(standard) + 至少 3 种资源类型执行 CRUD/ownership/tenant 对比 + CONTROL candidates 完整 + `unchecked=0`
- **D9 已覆盖** = 关键业务操作、状态、数值、并发和幂等不变量已枚举 + CONTROL candidates 完整 + `unchecked=0`
- **浅覆盖** = 仅 Grep 搜索 pattern 但未系统验证认证链、授权矩阵或业务不变量 / 缺少 CONTROL candidates / `unchecked>0`
- **未覆盖** = 未执行 Control-driven 审计
- **D3/D9 Agent 必须加载** `references/core/phase2_deep_methodology.md` Phase 2.5-2.6

### Config-driven 维度 (D2, D7, D8, D10)
- **已覆盖** = 核心配置项均已检查 + 版本/算法已对比安全基线 + CONFIG candidates 完整 + `unchecked=0`
- **浅覆盖** = 仅检查了部分配置 / 未深入验证 / 缺少 CONFIG candidates / `unchecked>0`
- **未覆盖** = 该维度未被任何 Agent 检查

### Memory-driven 维度 (D4)
- **已覆盖** = 适用的 allocation/bounds/ownership/free/use 与 Unsafe/FFI 类别已枚举 + MEMORY candidates 完整 + `unchecked=0`
- **浅覆盖** = 仅搜索危险 API，未验证长度、边界、所有权、生命周期或可达性
- **N/A** = D4 Agent 同时确认无反序列化、native、unsafe、FFI 攻击面，并保存运行原因与 checkpoint

## 终止判定

- 最终报告前，D1-D10 必须全部存在 durable Agent Run，且均已到达 reasoned terminal state
- `RUNNING/QUEUED/RESUMING/INTERRUPTED` 必须恢复原 Agent，不能以新一轮全量扫描替代
- `OPEN/TIMEOUT` 必须续跑关闭；达到轮次上限仍无法关闭时进入 Known Gaps，报告不得宣称 100% 覆盖
