# OpenCode Agents Security Audit Harness

本项目提供 OpenCode 代码安全审计 Agent，包含仓库级审计和功能级 Git 增量审计。Git 增量审计入口是 `git-diff-audit`，适合审计某个功能由多个 commit、PR、patch 或工作区改动共同实现后的安全风险。

## Git 增量审计

Git 增量审计固定使用 `git-diff-deep`，审计单位是**功能**，不是单个 hunk。最终漏洞必须绑定到：

- 功能语义
- Git 变更范围
- 真实代码证据
- 可达攻击路径

目标项目通过 `repo_root` 指定。不要把 `.codegraph/`、`.code-review-graph/` 放在本审计框架目录下，它们应该保存在被审计目标项目根目录。

## 审计前准备图数据库

如果希望启用 CodeGraph / code-review-graph 上下文，在审计前从本审计框架目录运行：

```bash
cd /Users/lousix/sec/ai4sec/opencode-agents

TARGET=/path/to/target/repo
python3 references/core/init_graph_context.py --repo "$TARGET" --mode update
```

该脚本会在目标项目下初始化或更新：

```text
<target_project>/.codegraph/
<target_project>/.code-review-graph/
```

并把以下内容写入目标项目本地 `.git/info/exclude`：

```text
.codegraph/
.code-review-graph/
.audit-work/
audit-reports/
```

查看状态：

```bash
python3 references/core/init_graph_context.py --repo "$TARGET" --mode status
```

`code-review-graph detect-changes` 对 `base` 很敏感。`base` 必须是本次审计范围之前的提交或目标分支 merge-base；如果传 `HEAD`，通常会得到 0 个 changed functions，即使 `.code-review-graph` 数据库本身有节点和边。审最近 10 个 commit 时，图上下文 base 通常应使用 `HEAD~10`。

Graph 数据不是报告装饰。审计时应先读取 `graph_context.json` 里的 `graph_review_queue`，按 priority 追踪 `changed_symbol -> caller_entrypoint -> callee_or_sink -> impact_file`，完成后再用普通 diff 文件列表补齐图未覆盖的文件。

## 方式一：自然语言调用

在 OpenCode 中可以直接用自然语言描述。关键是讲清楚：

- 目标项目路径
- 功能范围或功能名
- 代码范围：commit 列表、range、branch、patch 或 worktree
- 是否有功能文档

示例：审计 RAGSDK 最近 10 个 commit：
[模式区别详见Engine选择](#engine-选择)
```text
请使用 git-diff-audit 对项目 /path/to/target/repo 做一次功能级增量安全审计。

这次要审计的是最近 10 个 commit，请你从 commit message、diff 文件、入口点和代码语义中推断这 10 个 commit 共同实现的功能边界。

审计要求：
1. 使用 git-diff-deep。
2. 默认使用 autonomous/agents/hybrid 模式。
3. 审计单位是功能，不是单独 hunk。
4. 审计前请使用或检查 CodeGraph / code-review-graph 图上下文。
5. 图上下文 base 请使用 HEAD~10，不要使用 HEAD。
6. 请优先调用 audit_generate_diff_worklist 和 audit_generate_graph_context。
7. 生成 graph_context 后，请先按 graph_review_queue 的 priority 阅读和追踪代码，再按 diff 文件列表补齐覆盖。
8. 正式报告使用与 code-audit 相同的 audit-reports 格式；worklist 和 graph_context 只保存到 work_dir。

请从 /Users/lousix/sec/ai4sec/opencode-agents 这个审计框架目录运行，目标 repo_root 是 /path/to/target/repo。
```

如果已经知道 10 个 commit SHA：

```text
请使用 git-diff-audit 审计项目 /path/to/target/repo。

本次审计范围是以下 10 个 commit：
- abc123
- def456
- ...
- xyz999

这 10 个 commit 属于同一个功能，请你从 commit message 和代码 diff 推断功能画像，并进行功能级增量安全审计。若发现它们并不属于同一个功能，请按功能簇分组后分别审计。
请把图上下文 base 设置为这 10 个 commit 之前的提交，并优先消费 graph_review_queue。
```

如果知道功能名：

```text
请使用 git-diff-audit 审计 ~/Desktop/tmp/code/ascend/RAGSDK。

本次功能是“RAG 检索增强链路改造”，由以下 10 个 commit 实现：
- ...

请结合这些 commit 的 diff、调用链、配置变化和图上下文进行 deep-only 增量安全审计。
请先使用 graph_review_queue 导航 caller/callee/impact，再按普通 changed files 补齐覆盖。
重点关注：
- 用户输入到检索 query / prompt / tool 调用的流向
- 文件读取、知识库路径、模型服务请求
- SSRF、命令执行、反序列化、越权访问、敏感信息泄露
- 新增依赖和配置暴露
```

## 方式二：命令行调用

从本审计框架目录运行 OpenCode。不要用 `opencode run --dir <target> --agent git-diff-audit`，因为那会让 OpenCode 去目标项目里找 agent，可能找不到 `git-diff-audit`。

```bash
cd /path/to/opencode-agents

TARGET=/path/to/target/repo
```

审最近 10 个 commit：

```bash
COMMITS=$(git -C "$TARGET" rev-list --reverse --max-count=10 HEAD | paste -sd, -)
GRAPH_BASE=$(git -C "$TARGET" rev-parse HEAD~10)

opencode run --agent git-diff-audit --format default "
/git-audit --feature '最近10个commit实现的功能，请从commit message推断' \
  --repo-root $TARGET \
  --commits $COMMITS \
  --engine autonomous

请从这 10 个 commit 的 message、diff 和代码上下文推断功能边界，并做功能级增量安全审计。
请将 audit_generate_graph_context 的 base 设置为 $GRAPH_BASE，并先按 graph_review_queue 审计 caller/callee/impact，再补齐普通 diff 文件。
最终输出 audit-reports 正式报告路径；worklist 和 graph_context 状态记录到 .audit-work 下的 work_dir。
"
```

审一个连续 range：

```bash
opencode run --agent git-diff-audit --format default "
/git-audit --feature 'RAGSDK 功能增量审计' \
  --repo-root $TARGET \
  --range base_commit..head_commit \
  --engine autonomous

请对这个功能范围做 git-diff-deep 安全审计。
"
```

审明确的 10 个 commit：

```bash
COMMITS="sha1,sha2,sha3,sha4,sha5,sha6,sha7,sha8,sha9,sha10"

opencode run --agent git-diff-audit --format default "
/git-audit --feature 'RAGSDK 某功能改造' \
  --repo-root $TARGET \
  --commits $COMMITS \
  --engine autonomous

请按功能维度审计这 10 个 commit 的增量代码。
功能文档如果缺失，请从 commit message、变更文件、入口点和代码语义推断 FEATURE_PROFILE。
优先使用 audit_generate_diff_worklist 和 audit_generate_graph_context。
生成 graph_context 后必须先消费 graph_review_queue，不要只把 graph context 写入报告。
"
```

带功能文档：

```bash
opencode run --agent git-diff-audit --format default "
/git-audit --feature 'RAG 检索增强接口改造' \
  --repo-root $TARGET \
  --commits $COMMITS \
  --docs $TARGET/docs/rag-design.md \
  --engine autonomous

请结合功能文档和代码 diff 做功能级增量安全审计。
"
```

## Engine 选择

```text
autonomous  默认，AI 自主深挖，适合大多数功能增量审计
hybrid      自主主线 + 定向子 Agent，适合功能较大或风险类型较多
agents      强制多子 Agent 分工，适合需要结构化并行覆盖的场景
```

## 产物位置

增量审计与 Code Audit 使用相同的正式报告格式；Git Diff 特有材料放入独立的可恢复过程目录：

```text
<target_project>/audit-reports/
  index.md
  index.html
  details/
    <漏洞编号>-<组件名称>-<中文漏洞名称>.md

<target_project>/.audit-work/git-diff/<scan_id>/
  feature_review.md          # 过程记录，不属于正式交付报告
  02_worklist/
    diff_worklist.csv
    deep_review_input.csv
    work_ledger.md
  06_graph_context/
    graph_context.json
    graph_context.md
```

单漏洞只输出中文 Markdown；PoC、代码证据、修复方案与回归测试直接写入单漏洞报告。`index.md` 合并全部确认漏洞的完整正文，`index.html` 只保留轻量索引。不会生成 `report.md`、单漏洞 HTML 或 Git Diff 专属正式报告目录。Dockerfile、Compose 与 Docker 目录不进入审计、worklist 或 PoC 验证范围。

对项目 /Users/lousix/Desktop/tmp/code/ascend/MindIE-Motor 做一次功能级增量安全审计。
这次要审计的是最近 50 个 commit，请你从 commit message、diff 文件、入口点和代码语义中推断这 50 个 commit 实现的功能边界。

审计要求：
1. 使用 git-diff-deep。
2. 默认使用 autonomous 模式。
3. 审计单位是功能，不是单独 hunk。
4. 审计前请使用或检查 CodeGraph / code-review-graph 图上下文。
5. 请优先调用 audit_generate_diff_worklist 和 audit_generate_graph_context。
6. 最终输出与 code-audit 相同的 audit-reports 正式报告；worklist 与 graph_context 只写入 .audit-work 过程目录。

请从 /Users/lousix/sec/ai4sec/opencode-agents 这个审计框架目录运行，目标 repo_root 是 /Users/lousix/Desktop/tmp/code/ascend/MindIE-Motor
