import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

const agentsDir = new URL("../.opencode/agents/", import.meta.url);
const agentFiles = readdirSync(agentsDir)
  .filter((name) => name.endsWith(".md"))
  .map((name) => ({ name, text: readFileSync(new URL(name, agentsDir), "utf8") }));
const config = JSON.parse(readFileSync(new URL("../opencode.json", import.meta.url), "utf8"));
const codeAudit = readFileSync(new URL("../.opencode/agents/code-audit.md", import.meta.url), "utf8");
const verification = readFileSync(new URL("../.opencode/agents/audit-verification.md", import.meta.url), "utf8");
const harness = readFileSync(new URL("../.opencode/skills/audit-harness/SKILL.md", import.meta.url), "utf8");
const contract = readFileSync(new URL("../.opencode/skills/agent-contract/SKILL.md", import.meta.url), "utf8");

test("所有 Agent 显式禁用提问权限且不存在 ask 权限", () => {
  for (const { name, text } of agentFiles) {
    assert.match(text, /^permission:\n[\s\S]*?^  question: deny$/m, `${name} 未禁用 question`);
    assert.doesNotMatch(text, /^\s+\w+: ask$/m, `${name} 仍包含 ask 权限`);
  }
});

test("全局配置禁止提问并允许只读外部取证", () => {
  assert.equal(config.permission.question, "deny");
  assert.equal(config.permission.webfetch, "allow");
  assert.equal(config.permission.external_directory, "allow");
});

test("主调度器不等待确认且模糊模式自动采用 standard", () => {
  assert.match(codeAudit, /无法判定 \| 默认 `standard`/);
  assert.match(codeAudit, /计划生成后立即执行/);
  assert.match(codeAudit, /不得等待用户确认/);
  assert.doesNotMatch(codeAudit, /After user confirms|问用户，不得自行假设/);
});

test("上下文缺口使用保守推断而不是 ask_user", () => {
  assert.doesNotMatch(harness, /ask_user=/);
  assert.match(harness, /resolution=\{code_inference\|audit_context\|conservative_default\|unknown_recorded\}/);
  assert.match(contract, /不询问用户、不阻塞当前审计/);
});

test("动态验证缺少授权或环境时自动降级而不提问", () => {
  assert.match(verification, /全流程无人值守/);
  assert.match(verification, /不得向用户提问或等待确认/);
  assert.match(verification, /自动选择 `STATIC_REPRO`、`MANUAL_ONLY` 或 `NOT_REPRODUCED`/);
});
