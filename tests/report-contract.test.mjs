import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { runInNewContext } from "node:vm";
import { join, dirname, basename, relative } from "node:path";
import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";

const plugin = readFileSync(new URL("../.opencode/plugin/audit-db.js", import.meta.url), "utf8");
const verificationAgent = readFileSync(new URL("../.opencode/agents/audit-verification.md", import.meta.url), "utf8");
const reportAgent = readFileSync(new URL("../.opencode/agents/audit-report.md", import.meta.url), "utf8");
const config = JSON.parse(readFileSync(new URL("../opencode.json", import.meta.url), "utf8"));

function loadFindingRenderer() {
  const schemaNode = { describe() { return this; }, optional() { return this; } };
  const tool = Object.assign((definition) => definition, {
    schema: {
      number: () => Object.create(schemaNode),
      string: () => Object.create(schemaNode),
      boolean: () => Object.create(schemaNode),
    },
  });
  const runnable = plugin
    .replace(/^import .*;\n/gm, "")
    .replace("export default async (_ctx) =>", "const pluginExport = async (_ctx) =>");
  const context = {
    tool, Database: class {}, homedir, join, dirname, basename, relative, mkdirSync, existsSync,
    readFileSync, writeFileSync, createHash, process, console,
  };
  runInNewContext(`${runnable}\nglobalThis.renderFinding = generateFindingMarkdown;\nglobalThis.renderIndex = generateReportIndexMarkdown;\nglobalThis.evidenceQuality = detailedEvidenceQuality;\nglobalThis.titleSlug = reportTitleFileSlug;\nglobalThis.pocQuality = validatePocDetails;`, context);
  return context;
}

function normalizedPocCommands(values = {}) {
  const result = {};
  for (const field of ["poc_setup_commands", "poc_build_commands", "poc_run_commands",
    "poc_negative_control_commands", "poc_cleanup_commands"]) {
    const parsed = values[field] ?? [];
    result[field] = { parsed, value: JSON.stringify(parsed) };
  }
  return result;
}

test("逐漏洞 durable run 数据模型和工具齐全", () => {
  for (const table of ["finding_detail_runs", "finding_detail_checkpoints", "finding_report_details", "finding_report_artifacts"]) {
    assert.match(plugin, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  }
  for (const toolName of [
    "audit_list_findings_for_detail",
    "audit_start_finding_detail_run",
    "audit_checkpoint_finding_detail_run",
    "audit_get_finding_detail_context",
    "audit_save_finding_report_details",
    "audit_generate_finding_report",
    "audit_finish_finding_detail_run",
    "audit_generate_report_index",
  ]) {
    assert.match(plugin, new RegExp(`${toolName}:`), `${toolName} 未导出`);
  }
});

test("数据库 DDL 可由 SQLite 完整执行", () => {
  const start = plugin.indexOf("function initSchema");
  const end = plugin.indexOf("function normalizeSinkCandidateStatus", start);
  const schemaSource = plugin.slice(start, end);
  const statements = [...schemaSource.matchAll(/db\.run\(`([\s\S]*?)`/g)]
    .map((match) => match[1])
    .filter((statement) => !statement.includes("${"));
  const result = spawnSync("sqlite3", [":memory:"], {
    input: `PRAGMA foreign_keys=ON;\n${statements.map((statement) => `${statement};`).join("\n")}`,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);

  const insertStart = plugin.indexOf("INSERT INTO finding_report_details");
  const insertEnd = plugin.indexOf("ON CONFLICT(finding_id)", insertStart);
  const insert = plugin.slice(insertStart, insertEnd);
  const columns = insert.match(/\(([^)]*)\)\s*VALUES/s)[1].split(",").length;
  const values = insert.match(/VALUES\s*\(([^)]*)\)/s)[1];
  assert.equal(columns, (values.match(/\?/g) ?? []).length + 2, "报告详情 INSERT 列数与绑定值不一致");
});

test("单漏洞渲染为中文 Markdown 且不生成 HTML", () => {
  const start = plugin.indexOf("const auditGenerateFindingReport");
  const end = plugin.indexOf("const auditFinishFindingDetailRun", start);
  const toolSource = plugin.slice(start, end);
  assert.match(toolSource, /audit-reports", "details/);
  assert.match(toolSource, /writeFileSync\(markdownPath, markdown, "utf8"\)/);
  assert.match(toolSource, /html: null/);
  assert.doesNotMatch(toolSource, /writeFileSync\([^\n]*html/i);
  assert.match(toolSource, /`\$\{safeId\}-\$\{componentSlug\}-\$\{titleSlug\}\.md`/);

  for (const heading of [
    "一、风险与产品影响", "二、事实与根因", "三、代码与证据链",
    "四、攻击前置条件与利用场景", "五、安全影响与受影响范围",
    "六、安全核验与 PoC", "七、修复方案", "八、验收标准与回归测试",
    "九、关联位置与证据边界",
  ]) assert.match(plugin, new RegExp(heading));
});

test("单漏洞文件名可安全关联组件名称和中文漏洞名称", () => {
  const { titleSlug } = loadFindingRenderer();
  assert.equal(titleSlug("用户查询接口存在 SQL 注入"), "用户查询接口存在-SQL-注入");
  assert.equal(titleSlug("../越权读取:用户数据?"), "越权读取-用户数据");
  assert.equal(titleSlug("   "), "未命名漏洞");
});

test("单漏洞渲染结果面向产品且不混入整体报告信息", () => {
  const { renderFinding: render } = loadFindingRenderer();
  const markdown = render(
    { name: "示例产品" },
    { id: 7, vuln_id: "H-0007", severity: "High", vuln_type: "SQL 注入", cwe: "CWE-89",
      confidence: "HIGH", file_path: "src/UserDao.java", line_number: 42, poc: "id=1'" },
    { verdict: "VERIFIED", source_status: "TRUE_SOURCE", sink_status: "CONFIRMED",
      sanitizer_status: "NONE", exploitability: "PRACTICAL", severity_action: "KEEP" },
    { report_title: "用户查询接口存在 SQL 注入", component_name: "user-service",
      product_impact: "攻击者可读取或修改业务数据库中的用户数据。",
      affected_assets: '["用户查询接口","用户数据库"]', root_cause: "请求参数未经参数化处理即进入 SQL 执行函数。",
      attacker_profile: "具备普通账号的远程攻击者。", exploit_difficulty: "单次请求即可触发，利用难度较低。",
      preconditions: '["攻击者能够访问用户查询接口"]', attack_steps: '["登录普通账号并提交恶意查询参数"]',
      exploit_limitations: '["仅影响启用该查询功能的部署"]',
      cia_impact: '{"confidentiality":{"level":"高","impact":"可能泄露用户数据"},"integrity":{"level":"高","impact":"可能修改业务数据"}}',
      affected_scope: "影响用户查询模块及其访问的用户数据表。", poc_explanation: "仅在授权测试环境使用无害查询验证。",
      expected_result: "服务端执行了被拼接的查询条件。", verification_steps: '["发送无害边界字符并观察查询行为"]',
      poc_type: "EXECUTABLE_POC", poc_validation_status: "NOT_RUN", poc_language: "python",
      poc_source: "import requests\nresponse = requests.get(\"http://127.0.0.1/query\", params={\"id\": \"1'\"})\nprint(response.status_code)",
      poc_setup_commands: '[]', poc_build_commands: '[]', poc_run_commands: '["python3 poc.py"]',
      poc_expected_output: "服务端返回与正常查询不同的受控错误响应。", poc_observed_output: null,
      poc_negative_control_commands: '["python3 poc.py --id 1"]',
      poc_negative_control_expected: "正常参数返回成功响应且不出现数据库错误。", poc_cleanup_commands: '[]',
      poc_safety_notes: "仅连接已获授权的本地隔离测试服务，不读取或修改真实业务数据。",
      poc_execution_limitations: "当前仅审阅代码和命令，尚未启动目标服务。",
      immediate_mitigations: '["临时限制该接口只允许可信网络访问"]',
      required_fixes: '[{"priority":"P0","target":"UserDao.java:42","action":"改用参数化查询并移除字符串拼接。","rationale":"从根因上阻止输入改变 SQL 结构。","acceptance":"恶意字符按普通数据处理。"}]',
      acceptance_criteria: '["所有查询参数均通过绑定变量传入"]', regression_tests: '["验证正常查询、恶意输入、空值和越权场景"]',
      related_locations: '["src/UserDao.java:42"]', related_finding_ids: '[]',
      evidence_limitations: "结论基于当前分支代码，部署侧额外防护需上线前复核。" },
    [
      { step_type: "Source", file_path: "src/UserController.java", line_number: 18,
        function_name: "UserController.search", context_start_line: 14, context_end_line: 21,
        code_snippet: "String id = request.getParameter(\"id\");" },
      { step_type: "Sink", file_path: "src/UserDao.java", line_number: 42,
        function_name: "UserDao.search", context_start_line: 38, context_end_line: 45,
        code_snippet: "statement.executeQuery(sql);" },
    ],
  );
  assert.match(markdown, /攻击者可读取或修改业务数据库/);
  assert.match(markdown, /\| 组件名称 \| user-service \|/);
  assert.match(markdown, /优先级：P0/);
  assert.match(markdown, /相关函数：`UserController\.search`/);
  assert.match(markdown, /组件：`user-service`；相关函数：`UserController\.search`/);
  assert.match(markdown, /代码范围：`src\/UserController\.java:14-21`/);
  assert.match(markdown, /验收标准与回归测试/);
  assert.match(markdown, /\| 验证类型 \| 可执行 PoC \|/);
  assert.match(markdown, /```python\nimport requests/);
  assert.match(markdown, /```bash\npython3 poc\.py/);
  assert.match(markdown, /未执行，因此没有实际运行输出/);
  assert.doesNotMatch(markdown, /```text\nid=1'/);
  assert.doesNotMatch(markdown, /D1-D10|候选覆盖|漏洞总数|其他漏洞/);
  assert.doesNotMatch(markdown, /<html|<!doctype/i);
});

test("PoC 直接内嵌报告并强制区分预期与实际输出", () => {
  for (const column of ["poc_type", "poc_validation_status", "poc_source", "poc_run_commands",
    "poc_expected_output", "poc_observed_output", "poc_negative_control_commands",
    "poc_cleanup_commands", "poc_execution_limitations"]) {
    assert.match(plugin, new RegExp(`${column}\\s+TEXT`));
  }
  assert.match(verificationAgent, /全部内嵌在单漏洞 Markdown/);
  assert.match(verificationAgent, /不得创建独立 PoC 文件/);
  assert.match(plugin, /poc_observed_output is allowed only when validation status is EXECUTED or FAILED/);
  assert.match(plugin, /COMPLETED requires verification, structured PoC details, and current Markdown artifact/);
  assert.match(plugin, /error: "insufficient_poc_material"/);
  assert.doesNotMatch(plugin.slice(plugin.indexOf("function generateFindingMarkdown"), plugin.indexOf("function severityBadge")), /finding\.poc/);

  const { pocQuality } = loadFindingRenderer();
  const base = {
    poc_type: "EXECUTABLE_POC", poc_validation_status: "NOT_RUN", poc_language: "python",
    poc_source: "print('safe trigger')", poc_expected_output: "输出无害触发标记。",
    poc_negative_control_expected: "负向输入不会出现触发标记。", poc_safety_notes: "仅在授权隔离环境执行。",
  };
  const commands = normalizedPocCommands({
    poc_run_commands: ["python3 poc.py"], poc_negative_control_commands: ["python3 poc.py --negative"],
  });
  assert.equal(pocQuality(base, commands, { vuln_type: "SQL 注入" }, { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, undefined);
  assert.match(pocQuality({ ...base, poc_observed_output: "fabricated" }, commands,
    { vuln_type: "SQL 注入" }, { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, /allowed only/);
  assert.match(pocQuality({ ...base, poc_source: "// call target function\n// expect crash" }, commands,
    { vuln_type: "SQL 注入" }, { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, /comments only/);
  assert.match(pocQuality({ ...base, poc_source: "print('/Users/alice/private/checkout')" }, commands,
    { vuln_type: "SQL 注入" }, { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, /local absolute paths/);
  assert.match(pocQuality({ ...base, poc_type: "MANUAL_ONLY", poc_execution_limitations: "当前环境无法自动化执行。" },
    normalizedPocCommands(), { vuln_type: "SQL 注入" }, { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error,
    /require executable PoC/);
});

test("C/C++ 内存安全 PoC 必须带真实源码和 Sanitizer", () => {
  const { pocQuality } = loadFindingRenderer();
  const args = {
    poc_type: "EXECUTABLE_POC", poc_validation_status: "NOT_RUN", poc_language: "c",
    poc_source: "#include <stdio.h>\nint main(void) { puts(\"trigger\"); return 0; }",
    poc_expected_output: "触发越界访问并由地址消毒器报告。",
    poc_negative_control_expected: "边界内输入正常退出且无消毒器报告。",
    poc_safety_notes: "仅处理本地构造数据并在授权隔离环境执行。",
  };
  const noSanitizer = normalizedPocCommands({
    poc_build_commands: ["cc poc.c -o poc"], poc_run_commands: ["./poc"],
    poc_negative_control_commands: ["./poc --safe"],
  });
  assert.match(pocQuality(args, noSanitizer, { vuln_type: "堆缓冲区越界", cwe: "CWE-787" },
    { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, /ASAN\/UBSAN\/Valgrind/);
  const withSanitizer = normalizedPocCommands({
    poc_build_commands: ["cc -fsanitize=address poc.c -o poc"], poc_run_commands: ["./poc"],
    poc_negative_control_commands: ["./poc --safe"],
  });
  assert.equal(pocQuality(args, withSanitizer, { vuln_type: "堆缓冲区越界", cwe: "CWE-787" },
    { verdict: "VERIFIED", exploitability: "PRACTICAL" }).error, undefined);
});

test("误报保留排除原因但不生成单漏洞报告", () => {
  assert.match(plugin, /false_positive_no_individual_report/);
  assert.match(plugin, /REJECTED requires FALSE_POSITIVE or DROP verification/);
  assert.match(verificationAgent, /误报.*不生成修复报告/s);
});

test("中高危证据链要求函数名和足量代码上下文", () => {
  assert.match(plugin, /function_name TEXT/);
  assert.match(plugin, /context_start_line INTEGER/);
  assert.match(plugin, /context_end_line\s+INTEGER/);
  assert.match(plugin, /const minimumLines = \["Source", "Sink"\]\.includes\(type\) \? 8 : 5/);
  assert.match(plugin, /insufficient_code_context/);
  assert.match(verificationAgent, /Source 与 Sink 必须各保存至少 8 行/);
  const { evidenceQuality } = loadFindingRenderer();
  const eightLines = Array.from({ length: 8 }, (_, index) => `line ${index + 1}`).join("\n");
  const valid = evidenceQuality([
    { step_type: "Source", file_path: "a.js", line_number: 10, function_name: "api.input", code_snippet: eightLines },
    { step_type: "Sink", file_path: "b.js", line_number: 20, function_name: "db.query", code_snippet: eightLines },
  ], "High");
  assert.equal(valid.complete, true);
  const invalid = evidenceQuality([
    { step_type: "Source", file_path: "a.js", line_number: 10, code_snippet: "only one line" },
    { step_type: "Sink", file_path: "b.js", line_number: 20, function_name: "db.query", code_snippet: eightLines },
  ], "High");
  assert.equal(invalid.complete, false);
  assert.ok(invalid.issues.some((issue) => issue.reason.includes("函数名称")));
  assert.ok(invalid.issues.some((issue) => issue.reason.includes("至少需要 8 行")));
});

test("组件名称为产品报告必填项并进入文件名", () => {
  assert.match(plugin, /component_name is required/);
  assert.match(plugin, /missing_component_name/);
  assert.match(plugin, /`\$\{safeId\}-\$\{componentSlug\}-\$\{titleSlug\}\.md`/);
  assert.match(verificationAgent, /组件名称应使用产品、服务、包或模块的稳定名称/);
});

test("协调器强制每个 finding 独立分派并恢复断点", () => {
  assert.match(reportAgent, /每个 finding 必须由一次独立/);
  assert.match(reportAgent, /禁止把多个 ID 合并进一个 Prompt/);
  assert.match(reportAgent, /从断点继续/);
  assert.match(reportAgent, /index\.md.*合并所有确认漏洞的完整正文/s);
});

test("index.md 合并每个确认漏洞的完整 Markdown 正文", () => {
  assert.match(plugin, /readFileSync\(artifact\.markdown_path, "utf8"\)/);
  assert.match(plugin, /unreadable_finding_markdown_reports/);
  const { renderIndex } = loadFindingRenderer();
  const finding = { id: 7, vuln_id: "H-0007", title: "原始标题", report_title: "用户查询接口存在 SQL 注入",
    component_name: "user-service", severity: "High" };
  const markdown = renderIndex(
    { id: 3, mode: "standard", started_at: "2026-08-31" },
    { name: "示例产品" }, [finding],
    { 7: { severity_action: "KEEP" } }, { 7: { status: "COMPLETED" } },
    { 7: { markdown_path: "/project/audit-reports/details/H-0007-user-service-SQL注入.md",
      markdown_content: "# 【示例产品】【H-0007】用户查询接口存在 SQL 注入\n\n## 三、代码与证据链\n\n真实代码证据。\n\n## 六、安全核验与 PoC\n\n完整验证命令。\n\n## 七、修复方案\n\n参数化查询。" } },
    [], [], "/project/audit-reports",
  );
  assert.match(markdown, /# 示例产品 安全审计合并报告/);
  assert.match(markdown, /## 漏洞详细内容/);
  assert.match(markdown, /真实代码证据/);
  assert.match(markdown, /完整验证命令/);
  assert.match(markdown, /参数化查询/);
  assert.match(markdown, /\[独立 Markdown\]\(details\/H-0007-user-service-SQL注入\.md\)/);
  assert.doesNotMatch(markdown, /\]\(\/project\//);
});

test("OpenCode 配置指向新的报告 Agent", () => {
  assert.equal(config.agent["audit-verification"].prompt, "{file:.opencode/agents/audit-verification.md}");
  assert.equal(config.agent["audit-report"].prompt, "{file:.opencode/agents/audit-report.md}");
  assert.match(config.agent["audit-verification"].description, /Chinese Markdown only/);
});
