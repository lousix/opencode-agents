import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

const codeAudit = read("../.opencode/agents/code-audit.md");
const reportAgent = read("../.opencode/agents/audit-report.md");
const gitDiffAgent = read("../.opencode/agents/git-diff-audit.md");
const diffHarness = read("../.opencode/skills/audit-diff-harness/SKILL.md");
const artifactContract = read("../references/core/git_diff_artifacts.md");
const reportTemplate = read("../references/core/git_diff_report_template.md");
const graphContract = read("../references/core/graph_context_adapter.md");
const diffPlugin = read("../.opencode/plugin/git-diff-harness.js");
const worklistScript = read("../references/core/git_diff_worklist.py");

test("Git Diff 与 Code Audit 共享正式报告目录和逐漏洞文件名契约", () => {
  for (const source of [codeAudit, reportAgent, gitDiffAgent, diffHarness, artifactContract]) {
    assert.match(source, /audit-reports/);
    assert.match(source, /index\.md/);
    assert.match(source, /index\.html/);
    assert.match(source, /details/);
  }

  assert.match(gitDiffAgent, /report_dir = \{repo_root\}\/audit-reports/);
  assert.match(gitDiffAgent, /output_dir=\{report_dir\}/);
  assert.match(gitDiffAgent, /\{vuln_id\}-\{组件名称\}-\{中文漏洞名称\}\.md/);
  assert.match(diffHarness, /audit-reports\/details\/\{vuln_id\}-\{组件名称\}-\{中文漏洞名称\}\.md/);
  assert.match(artifactContract, /details\/<id>-<component>-<Chinese-title>\.md/);

  for (const source of [codeAudit, reportAgent, gitDiffAgent, diffHarness, artifactContract, reportTemplate]) {
    assert.doesNotMatch(source, /audit-reports\/findings|[</]findings\//);
  }
});

test("Git Diff 使用与报告协调器相同的完成回执", () => {
  for (const source of [reportAgent, gitDiffAgent]) {
    assert.match(source, /\[REPORT_DONE\]/);
    assert.match(source, /中文索引:/);
    assert.match(source, /浏览索引:/);
    assert.match(source, /确认漏洞:/);
    assert.match(source, /排除误报:/);
    assert.match(source, /单漏洞报告:/);
  }
  assert.doesNotMatch(gitDiffAgent, /\[REPORT_INDEX\]|\[FINDING_REPORTS\]|\[FEATURE_REVIEW\]/);
});

test("Git Diff 过程材料与正式报告隔离", () => {
  for (const source of [gitDiffAgent, diffHarness, artifactContract, reportTemplate, graphContract, diffPlugin]) {
    assert.doesNotMatch(source, /audit-output\/git-diff-scans/);
  }

  assert.match(gitDiffAgent, /work_dir = \{repo_root\}\/\.audit-work\/git-diff\/\{scan_id\}/);
  assert.match(gitDiffAgent, /\{work_dir\}\/feature_review\.md/);
  assert.match(artifactContract, /<work_dir>\/\n  feature_review\.md/);
  assert.match(reportTemplate, /<work_dir>\/feature_review\.md/);
  assert.match(diffPlugin, /join\(repoRoot, "\.audit-work", "git-diff", "tool-run"\)/);
  assert.match(diffPlugin, /join\(scanDir, "02_worklist", "diff_worklist\.csv"\)/);
  assert.match(diffPlugin, /join\(scanDir, "06_graph_context", "graph_context\.json"\)/);
  assert.doesNotMatch(diffPlugin, /join\(scanDir, "artifacts"/);
});

test("Git Diff 正式索引仍执行逐漏洞核验和数据库门禁", () => {
  assert.match(gitDiffAgent, /audit_list_findings_for_detail\(session_id, include_terminal=false\)/);
  assert.match(gitDiffAgent, /对每个 finding_id 单独 dispatch @audit-verification/);
  assert.match(gitDiffAgent, /audit_generate_report_index\(session_id, output_dir=\{report_dir\}, allow_unverified=false\)/);
  assert.match(gitDiffAgent, /断点续跑/);
  assert.match(diffHarness, /audit_generate_report_index\(session_id, output_dir=\{target_project\}\/audit-reports, allow_unverified=false\)/);
});

test("Git Diff worklist 明确排除 Docker 和生成的审计产物", () => {
  assert.match(worklistScript, /DOCKER_FILENAMES = \{/);
  for (const value of ["dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]) {
    assert.match(worklistScript, new RegExp(`"${value.replaceAll(".", "\\.")}"`));
  }
  assert.match(worklistScript, /"docker"/);
  assert.match(worklistScript, /"\.docker"/);
  assert.match(worklistScript, /"\.audit-work"/);
  assert.match(worklistScript, /"audit-reports"/);
  assert.match(worklistScript, /name\.startswith\("dockerfile\."\)/);
  assert.match(worklistScript, /name\.startswith\("docker-compose\."\)/);
  assert.match(worklistScript, /name\.startswith\("compose\."\)/);
  assert.match(worklistScript, /return "excluded_docker_content"/);
});
