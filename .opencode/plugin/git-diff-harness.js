import { tool } from "@opencode-ai/plugin/tool";
import { execFileSync } from "child_process";
import { existsSync, mkdirSync, readFileSync } from "fs";
import { dirname, join } from "path";

function resolveHarnessScript(ctx, harnessRoot, scriptName) {
  const roots = [
    harnessRoot,
    ctx?.directory,
    process.cwd(),
  ].filter(Boolean);
  for (const root of roots) {
    const scriptPath = join(root, "references", "core", scriptName);
    if (existsSync(scriptPath)) return scriptPath;
  }
  return join(roots[0] ?? process.cwd(), "references", "core", scriptName);
}

function runPythonJson(args, cwd) {
  try {
    const stdout = execFileSync("python3", args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120000,
      maxBuffer: 20 * 1024 * 1024,
    });
    return { ok: true, stdout: stdout.trim() };
  } catch (error) {
    return {
      ok: false,
      error: error?.message ?? String(error),
      stdout: String(error?.stdout ?? "").trim(),
      stderr: String(error?.stderr ?? "").trim(),
      status: error?.status ?? null,
    };
  }
}

const auditGenerateDiffWorklist = tool({
  description: "Generate deterministic Git diff worklists for feature-centric incremental security review.",
  args: {
    repo_root:     tool.schema.string().describe("Target repository root to inspect."),
    harness_root:  tool.schema.string().optional().describe("Audit harness root containing references/core/git_diff_worklist.py. Defaults to current OpenCode workspace."),
    scan_dir:      tool.schema.string().optional().describe("Resumable work directory. Defaults to {repo_root}/.audit-work/git-diff/tool-run."),
    out_path:      tool.schema.string().optional().describe("Output diff_worklist.csv path."),
    deep_out_path: tool.schema.string().optional().describe("Output deep_review_input.csv path."),
    mode:          tool.schema.string().optional().describe("worktree | staged | unstaged | commit | commits | range | patch | merge-base | base-head. Defaults to worktree."),
    base:          tool.schema.string().optional().describe("Git base ref for base-head or merge-base mode."),
    head:          tool.schema.string().optional().describe("Git head ref. Defaults to HEAD."),
    commit:        tool.schema.string().optional().describe("Commit SHA for commit mode."),
    commits:       tool.schema.string().optional().describe("Comma-separated commit SHAs for commits mode."),
    range:         tool.schema.string().optional().describe("Git range in base..head form for range mode."),
    patch:         tool.schema.string().optional().describe("Patch file path for patch mode."),
    area:          tool.schema.string().optional().describe("Area label for CSV rows. Defaults to feature-diff."),
    preview_bytes: tool.schema.number().optional().describe("Preview byte count. Defaults to 200."),
  },
  async execute(args, ctx) {
    const repoRoot = args.repo_root;
    const scanDir = args.scan_dir ?? join(repoRoot, ".audit-work", "git-diff", "tool-run");
    const outPath = args.out_path ?? join(scanDir, "02_worklist", "diff_worklist.csv");
    const deepOutPath = args.deep_out_path ?? join(scanDir, "02_worklist", "deep_review_input.csv");
    mkdirSync(dirname(outPath), { recursive: true });
    mkdirSync(dirname(deepOutPath), { recursive: true });

    const script = resolveHarnessScript(ctx, args.harness_root, "git_diff_worklist.py");
    if (!existsSync(script)) {
      return JSON.stringify({ error: "script_not_found", script });
    }

    const cmd = [
      script,
      "--repo", repoRoot,
      "--out", outPath,
      "--deep-out", deepOutPath,
      "--area", args.area ?? "feature-diff",
      "--preview-bytes", String(args.preview_bytes ?? 200),
      "--print-scope-hash",
    ];
    const mode = String(args.mode ?? "worktree").trim().toLowerCase();
    if (mode === "worktree") cmd.push("--worktree");
    else if (mode === "staged") cmd.push("--staged");
    else if (mode === "unstaged") cmd.push("--unstaged");
    else if (mode === "commit") cmd.push("--commit", args.commit ?? "");
    else if (mode === "commits") cmd.push("--commits", args.commits ?? "");
    else if (mode === "range") cmd.push("--range", args.range ?? "");
    else if (mode === "patch") cmd.push("--patch", args.patch ?? "");
    else if (mode === "merge-base") cmd.push("--merge-base", args.base ?? "", args.head ?? "HEAD");
    else if (mode === "base-head") cmd.push("--base", args.base ?? "", "--head", args.head ?? "HEAD");
    else return JSON.stringify({ error: "invalid_mode", mode });

    const result = runPythonJson(cmd, repoRoot);
    if (!result.ok) return JSON.stringify({ error: "worklist_failed", ...result, script });
    return JSON.stringify({
      ok: true,
      mode,
      repo_root: repoRoot,
      diff_worklist: outPath,
      deep_review_input: deepOutPath,
      scope_hash: result.stdout.split(/\s+/).filter(Boolean).pop() ?? "",
      script,
    });
  },
});

const auditGenerateGraphContext = tool({
  description: "Generate optional CodeGraph/code-review-graph context artifacts for feature-centric incremental security review.",
  args: {
    repo_root:     tool.schema.string().describe("Target repository root to inspect."),
    worklist_path: tool.schema.string().describe("deep_review_input.csv path from audit_generate_diff_worklist."),
    harness_root:  tool.schema.string().optional().describe("Audit harness root containing references/core/graph_context_adapter.py. Defaults to current OpenCode workspace."),
    scan_dir:      tool.schema.string().optional().describe("Resumable work directory. Defaults to {repo_root}/.audit-work/git-diff/tool-run."),
    out_json_path: tool.schema.string().optional().describe("Output graph_context.json path."),
    out_md_path:   tool.schema.string().optional().describe("Output graph_context.md path."),
    base:          tool.schema.string().optional().describe("Git diff base for graph providers. Defaults to HEAD."),
  },
  async execute(args, ctx) {
    const repoRoot = args.repo_root;
    const scanDir = args.scan_dir ?? join(repoRoot, ".audit-work", "git-diff", "tool-run");
    const outJsonPath = args.out_json_path ?? join(scanDir, "06_graph_context", "graph_context.json");
    const outMdPath = args.out_md_path ?? join(scanDir, "06_graph_context", "graph_context.md");
    mkdirSync(dirname(outJsonPath), { recursive: true });
    mkdirSync(dirname(outMdPath), { recursive: true });

    const script = resolveHarnessScript(ctx, args.harness_root, "graph_context_adapter.py");
    if (!existsSync(script)) {
      return JSON.stringify({ error: "script_not_found", script });
    }
    if (!existsSync(args.worklist_path)) {
      return JSON.stringify({ error: "worklist_not_found", worklist_path: args.worklist_path });
    }

    const cmd = [
      script,
      "--repo", repoRoot,
      "--worklist", args.worklist_path,
      "--base", args.base ?? "HEAD",
      "--out-json", outJsonPath,
      "--out-md", outMdPath,
    ];
    const result = runPythonJson(cmd, repoRoot);
    if (!result.ok) return JSON.stringify({ error: "graph_context_failed", ...result, script });

    let contextSummary = {};
    try {
      const context = JSON.parse(readFileSync(outJsonPath, "utf8"));
      contextSummary = {
        status: context.status,
        graph_confidence: context.graph_confidence,
        graph_first_required: Boolean(context.graph_first_required),
        risk_score: context.risk_score,
        providers: Array.isArray(context.providers)
          ? context.providers.map((p) => ({
              name: p.name,
              status: p.status,
              notes: p.notes ?? [],
              selection: p.selection ?? undefined,
            }))
          : [],
        raw_artifacts: context.raw_artifacts ?? {},
        graph_review_queue: Array.isArray(context.graph_review_queue) ? context.graph_review_queue.length : 0,
        graph_review_queue_top: Array.isArray(context.graph_review_queue)
          ? context.graph_review_queue.slice(0, 8).map((item) => ({
              priority: item.priority,
              kind: item.kind,
              symbol: item.symbol,
              file: item.file,
              line: item.line,
              reasons: item.reasons ?? [],
            }))
          : [],
        navigation_edges: Array.isArray(context.navigation_edges) ? context.navigation_edges.length : 0,
        supporting_files: Array.isArray(context.supporting_files) ? context.supporting_files.length : 0,
        affected_flows: Array.isArray(context.affected_flows) ? context.affected_flows.length : 0,
        test_gaps: Array.isArray(context.test_gaps) ? context.test_gaps.length : 0,
      };
    } catch {
      contextSummary = { parse_error: "graph_context.json could not be parsed" };
    }

    return JSON.stringify({
      ok: true,
      repo_root: repoRoot,
      graph_context_json: outJsonPath,
      graph_context_md: outMdPath,
      script,
      adapter_stdout: result.stdout,
      ...contextSummary,
    });
  },
});

export default async () => ({
  tool: {
    audit_generate_diff_worklist: auditGenerateDiffWorklist,
    audit_generate_graph_context: auditGenerateGraphContext,
  },
});
