import { tool } from "@opencode-ai/plugin";
import { Database } from "bun:sqlite";
import { homedir } from "os";
import { join, dirname, basename } from "path";
import { mkdirSync, existsSync, writeFileSync } from "fs";

// DB stored at ~/.opencode/audit.db — shared across all projects
const DB_PATH = join(homedir(), ".opencode", "audit.db");

function getDb() {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const db = new Database(DB_PATH);
  db.run("PRAGMA journal_mode=WAL");
  db.run("PRAGMA foreign_keys=ON");
  initSchema(db);
  return db;
}

function initSchema(db) {
  db.run(`CREATE TABLE IF NOT EXISTS projects (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    path       TEXT,
    language   TEXT,
    framework  TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_sessions (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER REFERENCES projects(id),
    mode        TEXT,
    rounds      INTEGER DEFAULT 1,
    status      TEXT DEFAULT 'running',
    started_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME,
    notes       TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY,
    session_id     INTEGER REFERENCES audit_sessions(id),
    vuln_id        TEXT,
    title          TEXT NOT NULL,
    severity       TEXT,
    cvss_score     REAL,
    cwe            TEXT,
    confidence     TEXT,
    file_path      TEXT,
    line_number    INTEGER,
    vuln_type      TEXT,
    description    TEXT,
    vuln_code      TEXT,
    attack_vector  TEXT,
    poc            TEXT,
    fix_suggestion TEXT,
    agent_source   TEXT,
    round_number   INTEGER DEFAULT 1,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sink_chains (
    id           INTEGER PRIMARY KEY,
    finding_id   INTEGER REFERENCES findings(id),
    step_order   INTEGER,
    step_type    TEXT,
    file_path    TEXT,
    line_number  INTEGER,
    code_snippet TEXT,
    notes        TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS finding_verifications (
    id                INTEGER PRIMARY KEY,
    finding_id        INTEGER REFERENCES findings(id),
    verifier_agent    TEXT,
    verdict           TEXT,
    source_status     TEXT,
    sink_status       TEXT,
    sanitizer_status  TEXT,
    exploitability    TEXT,
    severity_action   TEXT,
    true_source       TEXT,
    key_gap           TEXT,
    exploit_method    TEXT,
    conclusion        TEXT,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS attack_chains (
    id                INTEGER PRIMARY KEY,
    session_id        INTEGER REFERENCES audit_sessions(id),
    chain_title       TEXT,
    combined_severity TEXT,
    description       TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS attack_chain_steps (
    chain_id   INTEGER REFERENCES attack_chains(id),
    finding_id INTEGER REFERENCES findings(id),
    step_order INTEGER,
    link_desc  TEXT
  )`);
}

// ─── Tool definitions ────────────────────────────────────────────────────────

const auditInitSession = tool({
  description: "Initialize an audit session. Call once at the start of each audit. Returns session_id used by all other audit tools.",
  args: {
    project_name: tool.schema.string().describe("Project name (unique identifier)"),
    project_path: tool.schema.string().describe("Absolute path to the project being audited"),
    language:     tool.schema.string().optional().describe("Primary language, e.g. Python, Java, Go"),
    framework:    tool.schema.string().optional().describe("Framework, e.g. Django, Spring Boot"),
    mode:         tool.schema.string().optional().describe("Audit mode: standard | deep"),
    notes:        tool.schema.string().optional().describe("Notes for this session, e.g. 'post-fix retest round 2'"),
  },
  async execute(args) {
    const db = getDb();
    // Upsert project
    db.run(
      `INSERT INTO projects (name, path, language, framework)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET
         path      = excluded.path,
         language  = COALESCE(excluded.language, language),
         framework = COALESCE(excluded.framework, framework)`,
      [args.project_name, args.project_path, args.language ?? null, args.framework ?? null]
    );
    const project = db.query("SELECT id FROM projects WHERE name = ?").get(args.project_name);
    // Create new session
    const result = db.run(
      `INSERT INTO audit_sessions (project_id, mode, notes) VALUES (?, ?, ?)`,
      [project.id, args.mode ?? "standard", args.notes ?? null]
    );
    db.close();
    return JSON.stringify({ session_id: result.lastInsertRowid, project_id: project.id });
  },
});

const auditSaveFinding = tool({
  description: "Save a vulnerability finding to the database immediately upon discovery. Call this as soon as a vulnerability is identified, even if confidence is low.",
  args: {
    session_id:     tool.schema.number().describe("Session ID from audit_init_session"),
    title:          tool.schema.string().describe("Short vulnerability title, e.g. 'SQL Injection in UserController.search()'"),
    severity:       tool.schema.string().describe("Critical | High | Medium | Low | Info"),
    confidence:     tool.schema.string().describe("已验证 | 高置信 | 中置信 | 需验证"),
    vuln_type:      tool.schema.string().describe("Vulnerability type, e.g. SQLi, RCE, SSRF, XSS, IDOR"),
    file_path:      tool.schema.string().describe("Relative file path, e.g. src/controllers/user.py"),
    line_number:    tool.schema.number().optional().describe("Line number of the vulnerable code"),
    description:    tool.schema.string().describe("Detailed description of the vulnerability"),
    vuln_code:      tool.schema.string().optional().describe("The vulnerable code snippet"),
    attack_vector:  tool.schema.string().optional().describe("How an attacker would exploit this"),
    poc:            tool.schema.string().optional().describe("Proof of concept payload or steps"),
    fix_suggestion: tool.schema.string().optional().describe("Concrete fix recommendation"),
    agent_source:   tool.schema.string().optional().describe("Which agent found this, e.g. audit-d1-injection"),
    round_number:   tool.schema.number().optional().describe("Audit round number (default 1)"),
    cvss_score:     tool.schema.number().optional().describe("CVSS score 0.0-10.0"),
    cwe:            tool.schema.string().optional().describe("CWE identifier, e.g. CWE-89"),
  },
  async execute(args) {
    const db = getDb();
    const result = db.run(
      `INSERT INTO findings
         (session_id, title, severity, confidence, vuln_type, file_path, line_number,
          description, vuln_code, attack_vector, poc, fix_suggestion,
          agent_source, round_number, cvss_score, cwe)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        args.session_id, args.title, args.severity, args.confidence,
        args.vuln_type, args.file_path, args.line_number ?? null,
        args.description, args.vuln_code ?? null, args.attack_vector ?? null,
        args.poc ?? null, args.fix_suggestion ?? null,
        args.agent_source ?? null, args.round_number ?? 1,
        args.cvss_score ?? null, args.cwe ?? null,
      ]
    );
    db.close();
    return JSON.stringify({ finding_id: result.lastInsertRowid });
  },
});

const auditSaveSinkChain = tool({
  description: "Save sink chain nodes for a finding. Call after audit_save_finding with the finding_id. Pass steps as a JSON array.",
  args: {
    finding_id: tool.schema.number().describe("Finding ID from audit_save_finding"),
    steps: tool.schema.string().describe(
      'JSON array of sink chain steps. Each step: {"step_type":"Source|Transform|Sanitizer|Sink","file_path":"...","line_number":42,"code_snippet":"...","notes":"..."}'
    ),
  },
  async execute(args) {
    const db = getDb();
    let steps;
    try {
      steps = JSON.parse(args.steps);
    } catch {
      db.close();
      return JSON.stringify({ error: "steps must be a valid JSON array" });
    }
    if (!Array.isArray(steps)) {
      db.close();
      return JSON.stringify({ error: "steps must be a JSON array" });
    }
    const insert = db.prepare(
      `INSERT INTO sink_chains (finding_id, step_order, step_type, file_path, line_number, code_snippet, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      insert.run([args.finding_id, i, s.step_type ?? null, s.file_path ?? null,
                  s.line_number ?? null, s.code_snippet ?? null, s.notes ?? null]);
    }
    db.close();
    return JSON.stringify({ saved: steps.length });
  },
});

const auditSaveVerification = tool({
  description: "Save report-stage verification result for a finding. Call from audit-verification before final report generation.",
  args: {
    finding_id:       tool.schema.number().describe("Finding ID being verified"),
    verifier_agent:   tool.schema.string().optional().describe("Agent that performed verification"),
    verdict:          tool.schema.string().describe("VERIFIED | PARTIAL | SINK_ONLY | FALSE_POSITIVE"),
    source_status:    tool.schema.string().describe("TRUE_SOURCE | CONDITIONAL_SOURCE | PSEUDO_SOURCE | NO_SOURCE"),
    sink_status:      tool.schema.string().describe("CONFIRMED | UNCLEAR | NOT_FOUND"),
    sanitizer_status: tool.schema.string().describe("NONE | BYPASSABLE | EFFECTIVE | UNKNOWN"),
    exploitability:   tool.schema.string().describe("PRACTICAL | CONDITIONAL | THEORETICAL | NOT_EXPLOITABLE"),
    severity_action:  tool.schema.string().describe("KEEP | DOWNGRADE_1 | DOWNGRADE_2 | DROP"),
    true_source:      tool.schema.string().optional().describe("Verified source location and why it is attacker-controlled"),
    key_gap:          tool.schema.string().optional().describe("Missing or weak evidence in the chain"),
    exploit_method:   tool.schema.string().optional().describe("Practical attacker exploitation method"),
    conclusion:       tool.schema.string().optional().describe("Final verification conclusion"),
  },
  async execute(args) {
    const db = getDb();
    const result = db.run(
      `INSERT INTO finding_verifications
         (finding_id, verifier_agent, verdict, source_status, sink_status, sanitizer_status,
          exploitability, severity_action, true_source, key_gap, exploit_method, conclusion)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        args.finding_id, args.verifier_agent ?? null, args.verdict, args.source_status,
        args.sink_status, args.sanitizer_status, args.exploitability, args.severity_action,
        args.true_source ?? null, args.key_gap ?? null, args.exploit_method ?? null,
        args.conclusion ?? null,
      ]
    );
    db.close();
    return JSON.stringify({ verification_id: result.lastInsertRowid });
  },
});

const auditUpdateFindingAfterVerification = tool({
  description: "Update the canonical finding after verification. Use this to write back enriched root cause, exploit method, PoC, severity/confidence changes, and optionally replace the sink chain before final report generation.",
  args: {
    finding_id:       tool.schema.number().describe("Finding ID to update after verification"),
    title:            tool.schema.string().optional().describe("Updated vulnerability title"),
    severity:         tool.schema.string().optional().describe("Updated severity after verification"),
    confidence:       tool.schema.string().optional().describe("Updated confidence after verification"),
    vuln_type:        tool.schema.string().optional().describe("Updated vulnerability type"),
    file_path:        tool.schema.string().optional().describe("Updated primary file path"),
    line_number:      tool.schema.number().optional().describe("Updated primary line number"),
    description:      tool.schema.string().optional().describe("Updated vulnerability description"),
    vuln_code:        tool.schema.string().optional().describe("Updated key vulnerable code"),
    attack_vector:    tool.schema.string().optional().describe("Updated practical attacker exploit method"),
    poc:              tool.schema.string().optional().describe("Updated PoC payload or steps"),
    fix_suggestion:   tool.schema.string().optional().describe("Brief fix hint, if needed"),
    cvss_score:       tool.schema.number().optional().describe("Updated CVSS score"),
    cwe:              tool.schema.string().optional().describe("Updated CWE"),
    sink_chain_steps: tool.schema.string().optional().describe(
      'Optional JSON array replacing sink chain steps. Each step: {"step_type":"Source|Transform|Sanitizer|Sink","file_path":"...","line_number":42,"code_snippet":"...","notes":"..."}'
    ),
  },
  async execute(args) {
    const db = getDb();
    const existing = db.query("SELECT id FROM findings WHERE id=?").get(args.finding_id);
    if (!existing) {
      db.close();
      return JSON.stringify({ error: `Finding ${args.finding_id} not found` });
    }

    let replacementSteps;
    if (args.sink_chain_steps !== undefined) {
      try {
        replacementSteps = JSON.parse(args.sink_chain_steps);
      } catch {
        db.close();
        return JSON.stringify({ error: "sink_chain_steps must be a valid JSON array" });
      }
      if (!Array.isArray(replacementSteps)) {
        db.close();
        return JSON.stringify({ error: "sink_chain_steps must be a JSON array" });
      }
    }

    const updates = [];
    const values = [];
    const fields = [
      "title", "severity", "confidence", "vuln_type", "file_path", "line_number",
      "description", "vuln_code", "attack_vector", "poc", "fix_suggestion",
      "cvss_score", "cwe",
    ];
    for (const field of fields) {
      if (Object.prototype.hasOwnProperty.call(args, field)) {
        updates.push(`${field}=?`);
        values.push(args[field] ?? null);
      }
    }

    if (updates.length) {
      db.run(`UPDATE findings SET ${updates.join(", ")} WHERE id=?`, [...values, args.finding_id]);
    }

    let replaced_steps = 0;
    if (replacementSteps !== undefined) {
      db.run("DELETE FROM sink_chains WHERE finding_id=?", [args.finding_id]);
      const insert = db.prepare(
        `INSERT INTO sink_chains (finding_id, step_order, step_type, file_path, line_number, code_snippet, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      );
      for (let i = 0; i < replacementSteps.length; i++) {
        const s = replacementSteps[i];
        insert.run([args.finding_id, i, s.step_type ?? null, s.file_path ?? null,
                    s.line_number ?? null, s.code_snippet ?? null, s.notes ?? null]);
      }
      replaced_steps = replacementSteps.length;
    }

    db.close();
    return JSON.stringify({ ok: true, updated_fields: updates.length, replaced_steps });
  },
});

const auditGetFindingsForVerification = tool({
  description: "Fetch findings and sink chains that need report-stage verification for a session. Use this before dispatching audit-verification.",
  args: {
    session_id: tool.schema.number().describe("Session ID whose findings should be verified"),
    include_verified: tool.schema.boolean().optional().describe("Include findings that already have verification rows. Defaults to false."),
    finding_ids: tool.schema.string().optional().describe("Optional comma-separated finding IDs to fetch, e.g. '3,7,12'"),
  },
  async execute(args) {
    const db = getDb();
    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) { db.close(); return JSON.stringify({ error: `Session ${args.session_id} not found` }); }

    const where = ["session_id=?"];
    const params = [args.session_id];
    if (args.finding_ids) {
      const ids = args.finding_ids.split(",").map(s => parseInt(s.trim(), 10)).filter(Number.isFinite);
      if (!ids.length) {
        db.close();
        return JSON.stringify({ error: "finding_ids must contain at least one numeric ID" });
      }
      where.push(`id IN (${ids.map(() => "?").join(",")})`);
      params.push(...ids);
    }

    const rows = db.query(
      `SELECT * FROM findings WHERE ${where.join(" AND ")} ORDER BY
         CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         id`
    ).all(...params);

    const findings = [];
    for (const f of rows) {
      const latestVerification = db.query(
        "SELECT * FROM finding_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1"
      ).get(f.id);
      if (latestVerification && !args.include_verified) continue;

      const sinkChainSteps = db.query(
        "SELECT * FROM sink_chains WHERE finding_id=? ORDER BY step_order"
      ).all(f.id);
      findings.push({
        ...f,
        sink_chain_steps: sinkChainSteps,
        latest_verification: latestVerification ?? null,
      });
    }

    db.close();
    return JSON.stringify({
      session_id: args.session_id,
      count: findings.length,
      include_verified: Boolean(args.include_verified),
      findings,
    });
  },
});

const auditSaveAttackChain = tool({
  description: "Save a multi-finding attack chain (e.g. auth bypass → RCE). finding_ids and link_descs are comma-separated, ordered by chain step.",
  args: {
    session_id:        tool.schema.number().describe("Session ID"),
    chain_title:       tool.schema.string().describe("Attack chain title, e.g. 'Auth Bypass → RCE'"),
    combined_severity: tool.schema.string().describe("Combined severity: Critical | High | Medium"),
    description:       tool.schema.string().describe("Full description of the attack chain"),
    finding_ids:       tool.schema.string().describe("Comma-separated finding IDs in chain order, e.g. '3,7,12'"),
    link_descs:        tool.schema.string().optional().describe("Comma-separated descriptions of how each step enables the next"),
  },
  async execute(args) {
    const db = getDb();
    const chainResult = db.run(
      `INSERT INTO attack_chains (session_id, chain_title, combined_severity, description)
       VALUES (?, ?, ?, ?)`,
      [args.session_id, args.chain_title, args.combined_severity, args.description]
    );
    const chainId = chainResult.lastInsertRowid;
    const ids = args.finding_ids.split(",").map(s => parseInt(s.trim(), 10));
    const descs = args.link_descs ? args.link_descs.split(",") : [];
    const insertStep = db.prepare(
      `INSERT INTO attack_chain_steps (chain_id, finding_id, step_order, link_desc) VALUES (?, ?, ?, ?)`
    );
    for (let i = 0; i < ids.length; i++) {
      insertStep.run([chainId, ids[i], i, descs[i]?.trim() ?? null]);
    }
    db.close();
    return JSON.stringify({ chain_id: chainId });
  },
});

const auditCompleteSession = tool({
  description: "Mark an audit session as completed.",
  args: {
    session_id: tool.schema.number().describe("Session ID to mark as completed"),
  },
  async execute(args) {
    const db = getDb();
    db.run(
      `UPDATE audit_sessions SET status='completed', finished_at=CURRENT_TIMESTAMP WHERE id=?`,
      [args.session_id]
    );
    db.close();
    return JSON.stringify({ ok: true });
  },
});

const auditListSessions = tool({
  description: "List audit sessions, optionally filtered by project name. Useful to find session_id for report generation.",
  args: {
    project_name: tool.schema.string().optional().describe("Filter by project name (partial match)"),
  },
  async execute(args) {
    const db = getDb();
    let rows;
    if (args.project_name) {
      rows = db.query(
        `SELECT s.id, p.name as project, s.mode, s.status, s.rounds, s.started_at, s.notes
         FROM audit_sessions s JOIN projects p ON p.id=s.project_id
         WHERE p.name LIKE ?
         ORDER BY s.id DESC LIMIT 50`
      ).all(`%${args.project_name}%`);
    } else {
      rows = db.query(
        `SELECT s.id, p.name as project, s.mode, s.status, s.rounds, s.started_at, s.notes
         FROM audit_sessions s JOIN projects p ON p.id=s.project_id
         ORDER BY s.id DESC LIMIT 50`
      ).all();
    }
    db.close();
    if (!rows.length) return "No sessions found.";
    const header = "id | project | mode | status | started_at | notes";
    const sep = "-".repeat(80);
    const lines = rows.map(r =>
      `${r.id} | ${r.project} | ${r.mode} | ${r.status} | ${r.started_at} | ${r.notes ?? ""}`
    );
    return [header, sep, ...lines].join("\n");
  },
});

// ─── Report generation helpers ───────────────────────────────────────────────

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

function effectiveSeverity(f, verification) {
  const current = SEVERITY_ORDER.includes(f.severity) ? f.severity : "Info";
  const idx = SEVERITY_ORDER.indexOf(current);
  const action = verification?.severity_action;
  if (action === "DROP") return "Info";
  if (action === "DOWNGRADE_2") return SEVERITY_ORDER[Math.min(idx + 2, SEVERITY_ORDER.length - 1)];
  if (action === "DOWNGRADE_1") return SEVERITY_ORDER[Math.min(idx + 1, SEVERITY_ORDER.length - 1)];
  return current;
}

function severityBadge(s) {
  const colors = { Critical: "#d32f2f", High: "#f57c00", Medium: "#fbc02d", Low: "#388e3c", Info: "#1976d2" };
  return `<span style="background:${colors[s]??'#888'};color:#fff;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:bold">${s}</span>`;
}

function escapeHtml(s) {
  if (!s) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function reportProjectName(project) {
  return String(project?.name ?? "").trim()
    || (project?.path ? basename(project.path) : "")
    || "未命名项目";
}

function reportFileProjectName(project) {
  return reportProjectName(project)
    .replace(/[\\/:*?"<>|]/g, "-")
    .replace(/\s+/g, "_")
    .replace(/-+/g, "-")
    .replace(/_+/g, "_")
    .replace(/^[-_.]+|[-_.]+$/g, "")
    || "未命名项目";
}

function reportTimestamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function escapeMdCell(s) {
  return String(s ?? "-").replace(/\|/g, "\\|").replace(/\n/g, "<br>").trim() || "-";
}

function compactText(s, max = 220) {
  const text = String(s ?? "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function langForPath(filePath) {
  const ext = (filePath ?? "").split(".").pop()?.toLowerCase();
  const map = {
    java: "java", py: "python", go: "go", php: "php", js: "javascript", ts: "typescript",
    jsx: "jsx", tsx: "tsx", rb: "ruby", rs: "rust", cs: "csharp", cpp: "cpp", cc: "cpp",
    c: "c", h: "c", hpp: "cpp", xml: "xml", yml: "yaml", yaml: "yaml", json: "json",
    properties: "properties", toml: "toml", sql: "sql", sh: "bash"
  };
  return map[ext] ?? "";
}

function normalizeStepType(type) {
  const t = String(type ?? "").trim();
  if (!t) return "Step";
  if (/source/i.test(t)) return "Source";
  if (/sink/i.test(t)) return "Sink";
  if (/saniti[sz]er|filter|validate|escape/i.test(t)) return "Sanitizer";
  if (/transform|propagat|build|convert|process/i.test(t)) return "Transform";
  return t;
}

function stepLocation(s) {
  return s.file_path ? `${s.file_path}${s.line_number ? `:${s.line_number}` : ""}` : "-";
}

function stepSummary(s) {
  const type = normalizeStepType(s.step_type);
  const code = s.code_snippet ? compactText(s.code_snippet, 140) : "";
  const note = s.notes ? compactText(s.notes, 160) : "";
  if (note && code) return `${note} | ${code}`;
  return note || code || "-";
}

function sourceStatusForSteps(steps) {
  const source = steps.find(s => normalizeStepType(s.step_type) === "Source");
  if (!source) return "NO_SOURCE";
  const text = `${source.notes ?? ""} ${source.code_snippet ?? ""}`.toLowerCase();
  if (/pseudo|constant|test|mock|fixture|internal only|no_source|not user/i.test(text)) return "PSEUDO_SOURCE";
  if (/admin|config|profile|operator|deployment|conditional/i.test(text)) return "CONDITIONAL_SOURCE";
  return "TRUE_SOURCE";
}

function buildFlowLine(steps) {
  if (!steps.length) return "";
  return steps.map(s => {
    const type = normalizeStepType(s.step_type);
    const loc = stepLocation(s);
    return loc === "-" ? type : `${type}(${loc})`;
  }).join("\n  -> ");
}

function buildRootCause(f, steps) {
  const source = steps.find(s => normalizeStepType(s.step_type) === "Source");
  const sink = steps.findLast?.(s => normalizeStepType(s.step_type) === "Sink")
    ?? [...steps].reverse().find(s => normalizeStepType(s.step_type) === "Sink");
  const sanitizers = steps.filter(s => normalizeStepType(s.step_type) === "Sanitizer");
  if (!steps.length) {
    return `当前记录尚未包含 Source→Sink 数据流证据。该发现需要在报告前复核阶段补充真实 Source 和 Sink 可达性，否则应降级或移出最终报告。`;
  }
  if (!source) {
    return `当前链路只记录到危险点${sink ? ` ${stepLocation(sink)}` : ""}，但未保存真实外部 Source。该发现不能支撑高危结论，报告前复核应重点确认攻击者是否能够控制进入 Sink 的数据。`;
  }
  const sourceLoc = stepLocation(source);
  const sinkLoc = sink ? stepLocation(sink) : "未记录 Sink";
  const sanitizerText = sanitizers.length
    ? `链路中记录了 ${sanitizers.length} 个净化/校验节点，需要确认是否可绕过。`
    : "链路中未记录有效净化、参数化、白名单或权限拦截。";
  return `攻击者可控输入从 ${sourceLoc} 进入系统，经业务转换后到达 ${sinkLoc}。${sanitizerText} 根因是外部输入在到达危险操作前缺少有效安全边界控制，导致 ${f.vuln_type ?? "该类漏洞"} 可被触发。`;
}

function buildExploitMethod(f, steps) {
  if (f.attack_vector) return f.attack_vector;
  const source = steps.find(s => normalizeStepType(s.step_type) === "Source");
  const sink = steps.findLast?.(s => normalizeStepType(s.step_type) === "Sink")
    ?? [...steps].reverse().find(s => normalizeStepType(s.step_type) === "Sink");
  if (!source || !sink) {
    return "当前记录未提供完整攻击路径。报告前复核必须补充攻击者可控入口、关键参数、触发 Sink 的请求或操作步骤。";
  }
  return `攻击者控制 ${stepLocation(source)} 处的输入，使其沿业务调用链传播到 ${stepLocation(sink)} 的危险操作。若中间不存在有效净化或权限限制，即可触发 ${f.vuln_type ?? "漏洞"} 影响。`;
}

function buildFixBrief(f) {
  if (!f.fix_suggestion) return "";
  return compactText(f.fix_suggestion, 360);
}

function reportOrderedFindings(findings, verificationMap = {}) {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER.indexOf(effectiveSeverity(a, verificationMap[a.id]))
      - SEVERITY_ORDER.indexOf(effectiveSeverity(b, verificationMap[b.id]));
    return sevDiff || a.id - b.id;
  });
}

function assignVulnIds(findings, verificationMap = {}) {
  const prefixMap = { Critical: "C", High: "H", Medium: "M", Low: "L", Info: "I" };
  const idxMap = {};
  for (const f of reportOrderedFindings(findings, verificationMap)) {
    const p = prefixMap[effectiveSeverity(f, verificationMap[f.id])] ?? "X";
    idxMap[p] = (idxMap[p] ?? 0) + 1;
    f._vid = `${p}-${String(idxMap[p]).padStart(2, "0")}`;
  }
}

function stepJudgment(step, verification) {
  const type = normalizeStepType(step.step_type);
  if (type === "Source") return verification?.source_status ?? "TRUE_SOURCE";
  if (type === "Sink") return verification?.sink_status ?? "CONFIRMED";
  if (type === "Sanitizer") return verification?.sanitizer_status ?? "UNKNOWN";
  return step.notes ? compactText(step.notes, 120) : "传播节点";
}

function fallbackFlowSteps(f) {
  if (!f?.file_path && !f?.vuln_code) return [];
  return [{
    step_type: "Sink",
    file_path: f.file_path,
    line_number: f.line_number,
    code_snippet: f.vuln_code,
    notes: "数据库未记录完整 Source→Sink 链，当前仅保留主漏洞位置。",
  }];
}

function findingVerificationStatus(f, steps, verification) {
  if (verification?.verdict) return verification.verdict;
  if (!steps.length) return "NO_CHAIN";
  const sourceStatus = sourceStatusForSteps(steps);
  const hasSink = steps.some(s => normalizeStepType(s.step_type) === "Sink");
  if (sourceStatus === "TRUE_SOURCE" && hasSink) return "VERIFIED";
  if (sourceStatus === "NO_SOURCE" && hasSink) return "SINK_ONLY";
  if (!hasSink) return "PARTIAL";
  return sourceStatus;
}

function verificationSourceStatus(steps, verification) {
  return verification?.source_status || (steps.length ? sourceStatusForSteps(steps) : "NO_CHAIN");
}

function verificationAction(verification, fallbackVerification, sourceStatus) {
  if (verification?.severity_action) return verification.severity_action;
  return fallbackVerification === "VERIFIED" ? "KEEP"
    : fallbackVerification === "SINK_ONLY" || sourceStatus === "NO_SOURCE" ? "DOWNGRADE/DROP"
    : "REVIEW";
}

function buildVerificationSummaryMd(findings, sinkMap, verificationMap = {}) {
  if (!findings.length) return "";
  const rows = findings.map(f => {
    const steps = sinkMap[f.id] ?? [];
    const verification = verificationMap[f.id];
    const status = findingVerificationStatus(f, steps, verification);
    const sourceStatus = verificationSourceStatus(steps, verification);
    const action = verificationAction(verification, status, sourceStatus);
    const sev = effectiveSeverity(f, verification);
    const sevText = sev === f.severity ? sev : `${f.severity} -> ${sev}`;
    return `| ${f._vid ?? f.id} | ${escapeMdCell(f.title)} | ${escapeMdCell(sevText)} | ${escapeMdCell(status)} | ${escapeMdCell(sourceStatus)} | ${escapeMdCell(action)} |`;
  }).join("\n");
  return `## 真实性复核摘要\n\n| ID | 漏洞 | 等级 | 复核状态 | Source 状态 | 建议动作 |\n|----|------|------|----------|-------------|----------|\n${rows}\n\n`;
}

function buildVerificationSummaryHtml(findings, sinkMap, verificationMap = {}) {
  if (!findings.length) return "";
  const rows = findings.map(f => {
    const steps = sinkMap[f.id] ?? [];
    const verification = verificationMap[f.id];
    const status = findingVerificationStatus(f, steps, verification);
    const sourceStatus = verificationSourceStatus(steps, verification);
    const action = verificationAction(verification, status, sourceStatus);
    const sev = effectiveSeverity(f, verification);
    const sevText = sev === f.severity ? severityBadge(sev) : `${severityBadge(f.severity)} → ${severityBadge(sev)}`;
    return `<tr>
      <td><a href="#${escapeHtml(f._vid ?? String(f.id))}">${escapeHtml(f._vid ?? String(f.id))}</a></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${sevText}</td>
      <td>${escapeHtml(status)}</td>
      <td>${escapeHtml(sourceStatus)}</td>
      <td>${escapeHtml(action)}</td>
    </tr>`;
  }).join("\n");
  return `<h2>真实性复核摘要</h2>
  <table style="border-collapse:collapse;width:100%;font-size:0.9em;margin:16px 0;background:#fff">
    <thead><tr style="background:#f1f3f5">
      <th style="text-align:left;padding:8px;border:1px solid #ddd">ID</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">漏洞</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">等级</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">复核状态</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">Source 状态</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">建议动作</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function buildSinkChainMd(steps, f, verification) {
  const displaySteps = steps.length ? steps : fallbackFlowSteps(f);
  const sourceStatus = verificationSourceStatus(displaySteps, verification);
  const warning = sourceStatus === "TRUE_SOURCE"
    ? ""
    : `> 真实性提示: 当前链路 Source 状态为 **${sourceStatus}**，若无法补齐真实 Source，最终等级应降级。\n\n`;

  if (!displaySteps.length) {
    return `#### 四、数据流总览\n\n_当前数据库未记录 Source→Sink 数据流。该项不能作为高危结论展示，应先完成复核补链。_\n\n#### 五、漏洞数据流分析 / 关键代码分析\n\n_当前数据库未记录关键代码片段。_\n`;
  }

  const flow = `\`\`\`text\n${buildFlowLine(displaySteps)}\n\`\`\``;
  const rows = displaySteps.map(s =>
    `| ${escapeMdCell(normalizeStepType(s.step_type))} | \`${escapeMdCell(stepLocation(s))}\` | - | ${escapeMdCell(stepSummary(s))} | ${escapeMdCell(stepJudgment(s, verification))} |`
  ).join("\n");
  const table = `| 阶段 | 位置 | 变量/对象 | 处理 | 安全判断 |\n|------|------|-----------|------|----------|\n${rows}`;
  const codeBlocks = displaySteps.map((s, i) => {
    const type = normalizeStepType(s.step_type);
    const loc = stepLocation(s);
    const lang = langForPath(s.file_path);
    const snippet = String(s.code_snippet ?? "").trim();
    const code = snippet
      ? `\`\`\`${lang}\n${snippet}\n\`\`\``
      : `_当前节点未保存代码片段，复核阶段应补充 Read 证据。_`;
    const note = s.notes ? `\n\n判断: ${s.notes}` : "";
    return `##### ${i + 1}. ${type}: ${type === "Source" ? "用户输入进入系统" : type === "Sink" ? "危险函数被触发" : "输入传播或安全处理"}\n\n位置: \`${loc}\`\n\n${code}${note}`;
  }).join("\n\n");
  return `#### 四、数据流总览\n\n${warning}${flow}\n\n${table}\n\n#### 五、漏洞数据流分析 / 关键代码分析\n\n${codeBlocks}\n`;
}

function buildSinkChainHtml(steps, f, verification) {
  const displaySteps = steps.length ? steps : fallbackFlowSteps(f);
  if (!displaySteps.length) {
    return `<section><h4>四、数据流总览</h4><p><em>当前数据库未记录 Source→Sink 数据流。该项不能作为高危结论展示，应先完成复核补链。</em></p></section>
      <section><h4>五、漏洞数据流分析 / 关键代码分析</h4><p><em>当前数据库未记录关键代码片段。</em></p></section>`;
  }

  const sourceStatus = verificationSourceStatus(displaySteps, verification);
  const flow = escapeHtml(buildFlowLine(displaySteps));
  const warning = sourceStatus === "TRUE_SOURCE" ? "" :
    `<div style="border-left:4px solid #d9822b;background:#fff8e8;padding:8px 12px;margin:10px 0;color:#6f4a00">
      真实性提示: 当前链路 Source 状态为 <strong>${escapeHtml(sourceStatus)}</strong>，若无法补齐真实 Source，最终等级应降级。
    </div>`;
  const tableRows = displaySteps.map(s => `
    <tr>
      <td><strong>${escapeHtml(normalizeStepType(s.step_type))}</strong></td>
      <td><code>${escapeHtml(stepLocation(s))}</code></td>
      <td>-</td>
      <td>${escapeHtml(stepSummary(s))}</td>
      <td>${escapeHtml(stepJudgment(s, verification))}</td>
    </tr>`).join("\n");
  const codeBlocks = displaySteps.map((s, i) => {
    const type = normalizeStepType(s.step_type);
    const loc = stepLocation(s);
    const title = type === "Source" ? "用户输入进入系统" : type === "Sink" ? "危险函数被触发" : "输入传播或安全处理";
    const snippet = s.code_snippet
      ? `<pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">${escapeHtml(s.code_snippet)}</pre>`
      : `<p style="color:#777;font-style:italic">当前节点未保存代码片段，复核阶段应补充 Read 证据。</p>`;
    const note = s.notes ? `<p style="margin:6px 0;color:#444"><strong>判断:</strong> ${escapeHtml(s.notes)}</p>` : "";
    return `<section style="margin:14px 0">
      <h5 style="margin:0 0 6px;font-size:0.95em">${i + 1}. ${escapeHtml(type)}: ${escapeHtml(title)}</h5>
      <p style="margin:0 0 6px">位置: <code>${escapeHtml(loc)}</code></p>
      ${snippet}
      ${note}
    </section>`;
  }).join("\n");
  return `
    <section style="margin:12px 0"><h4 style="margin:0 0 6px">四、数据流总览</h4>
      ${warning}
      <pre style="background:#eef2f5;color:#263238;padding:10px 12px;border-radius:4px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">${flow}</pre>
      <table style="border-collapse:collapse;width:100%;font-size:0.88em;margin:10px 0">
        <thead><tr style="background:#f1f3f5"><th style="text-align:left;padding:6px;border:1px solid #ddd">阶段</th><th style="text-align:left;padding:6px;border:1px solid #ddd">位置</th><th style="text-align:left;padding:6px;border:1px solid #ddd">变量/对象</th><th style="text-align:left;padding:6px;border:1px solid #ddd">处理</th><th style="text-align:left;padding:6px;border:1px solid #ddd">安全判断</th></tr></thead>
        <tbody>${tableRows}</tbody>
      </table>
    </section>
    <section style="margin:12px 0"><h4 style="margin:0 0 6px">五、漏洞数据流分析 / 关键代码分析</h4>${codeBlocks}</section>`;
}

function generateMarkdown(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap = {}) {
  const date = new Date().toISOString().slice(0, 10);
  const projectName = reportProjectName(project);
  assignVulnIds(findings, verificationMap);
  const orderedFindings = reportOrderedFindings(findings, verificationMap);
  const counts = {};
  for (const s of SEVERITY_ORDER) counts[s] = findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === s).length;

  let md = `# 安全审计报告\n\n`;
  md += `**项目**: ${projectName}  \n`;
  md += `**路径**: ${project.path ?? "-"}  \n`;
  md += `**技术栈**: ${[project.language, project.framework].filter(Boolean).join(" / ") || "-"}  \n`;
  md += `**审计模式**: ${session.mode ?? "-"}  \n`;
  md += `**审计时间**: ${session.started_at}  \n`;
  md += `**报告生成**: ${date}  \n`;
  if (session.notes) md += `**备注**: ${session.notes}  \n`;
  md += `\n---\n\n`;

  md += `## 执行摘要\n\n`;
  md += `| 等级 | 数量 |\n|------|------|\n`;
  for (const s of SEVERITY_ORDER) md += `| ${s} | ${counts[s]} |\n`;
  md += `| **合计** | **${findings.length}** |\n\n`;

  md += buildVerificationSummaryMd(orderedFindings, sinkMap, verificationMap);

  md += `## 漏洞详情\n\n`;
  for (const f of orderedFindings) {
    const steps = sinkMap[f.id] ?? [];
    const verification = verificationMap[f.id];
    const reportSeverity = effectiveSeverity(f, verification);
    const status = findingVerificationStatus(f, steps, verification);
    const sourceStatus = verificationSourceStatus(steps, verification);
    const action = verificationAction(verification, status, sourceStatus);
    const fixBrief = buildFixBrief(f);

    md += `### 【${projectName}】【${f._vid}】${f.title}\n\n`;
    md += `| 属性 | 值 |\n|------|----|\n`;
    md += `| 漏洞名称 | ${escapeMdCell(f.title)} |\n`;
    md += `| 严重程度 | ${reportSeverity} |\n`;
    if (reportSeverity !== f.severity) md += `| 原始等级 | ${f.severity} |\n`;
    if (f.cvss_score != null) md += `| CVSS | ${f.cvss_score} |\n`;
    if (f.cwe) md += `| CWE | ${escapeMdCell(f.cwe)} |\n`;
    md += `| 置信度 | ${escapeMdCell(f.confidence)} |\n`;
    md += `| 漏洞类型 | ${escapeMdCell(f.vuln_type)} |\n`;
    md += `| 复核结论 | ${escapeMdCell(`${status} / ${sourceStatus} / ${action}`)} |\n`;
    md += `| 位置 | \`${escapeMdCell(f.file_path ?? "-")}${f.line_number ? `:${f.line_number}` : ""}\` |\n`;
    if (f.agent_source) md += `| 发现Agent | ${escapeMdCell(f.agent_source)} |\n`;
    md += `\n`;
    md += `#### 一、漏洞描述\n\n${f.description || "报告阶段未记录漏洞描述，需回看原始 finding。"}\n\n`;
    md += `#### 二、漏洞根因\n\n${buildRootCause(f, steps)}\n\n`;
    md += `#### 三、攻击者利用方法\n\n${verification?.exploit_method || buildExploitMethod(f, steps)}\n\n`;
    md += `${buildSinkChainMd(steps, f, verification)}\n`;
    md += `#### 六、PoC\n\n`;
    md += f.poc ? `\`\`\`text\n${f.poc}\n\`\`\`\n\n` : `_报告阶段未记录 PoC，需结合上述攻击者利用方法补充最小复现步骤。_\n\n`;
    md += `#### 七、修复提示\n\n${fixBrief || "仅保留最短修复方向：在真实 Source 到 Sink 的边界增加有效校验、参数化或白名单控制。"}\n\n`;
    md += `#### 八、参考\n\n${f.cwe ? `- ${f.cwe}` : "- 暂无 CWE 记录"}\n\n`;
    md += `---\n\n`;
  }

  if (attackChains.length) {
    md += `## 攻击链分析\n\n`;
    for (const chain of attackChains) {
      md += `### ${chain.chain_title} [${chain.combined_severity}]\n\n`;
      md += `${chain.description}\n\n`;
      const steps = chainSteps.filter(s => s.chain_id === chain.id);
      if (steps.length) {
        md += `**攻击路径**:\n\n`;
        for (const s of steps) {
          const f = findings.find(x => x.id === s.finding_id);
          md += `${s.step_order + 1}. **[${f?._vid ?? s.finding_id}]** ${f?.title ?? "Unknown"}`;
          if (s.link_desc) md += ` → ${s.link_desc}`;
          md += `\n`;
        }
        md += `\n`;
      }
    }
  }

  return md;
}

function generateHtml(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap = {}) {
  const date = new Date().toISOString().slice(0, 10);
  const projectName = reportProjectName(project);
  assignVulnIds(findings, verificationMap);
  const orderedFindings = reportOrderedFindings(findings, verificationMap);
  const counts = {};
  for (const s of SEVERITY_ORDER) counts[s] = findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === s).length;

  const statCards = SEVERITY_ORDER.map(s => {
    const colors = { Critical: "#d32f2f", High: "#f57c00", Medium: "#fbc02d", Low: "#388e3c", Info: "#1976d2" };
    return `<div style="background:${colors[s]};color:#fff;padding:16px 24px;border-radius:8px;text-align:center;min-width:100px">
      <div style="font-size:2em;font-weight:bold">${counts[s]}</div>
      <div style="font-size:0.9em;margin-top:4px">${s}</div>
    </div>`;
  }).join("\n");

  let findingsHtml = "";
  for (const f of orderedFindings) {
    const steps = sinkMap[f.id] ?? [];
    const verification = verificationMap[f.id];
    const reportSeverity = effectiveSeverity(f, verification);
    const status = findingVerificationStatus(f, steps, verification);
    const sourceStatus = verificationSourceStatus(steps, verification);
    const action = verificationAction(verification, status, sourceStatus);
    const rootCause = buildRootCause(f, steps);
    const exploitMethod = verification?.exploit_method || buildExploitMethod(f, steps);
    const fixBrief = buildFixBrief(f) || "仅保留最短修复方向：在真实 Source 到 Sink 的边界增加有效校验、参数化或白名单控制。";
    findingsHtml += `
    <article id="${f._vid}" style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:20px;margin:18px 0;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <h3 style="margin:0 0 12px">【${escapeHtml(projectName)}】【${f._vid}】${escapeHtml(f.title)} ${severityBadge(reportSeverity)}</h3>
      <table style="border-collapse:collapse;font-size:0.9em;margin-bottom:14px">
        <tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">漏洞名称</td><td>${escapeHtml(f.title)}</td></tr>
        <tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">严重程度</td><td>${severityBadge(reportSeverity)}</td></tr>
        ${reportSeverity !== f.severity ? `<tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">原始等级</td><td>${severityBadge(f.severity)}</td></tr>` : ""}
        ${f.cvss_score != null ? `<tr><td style="padding:3px 12px 3px 0;color:#666">CVSS</td><td>${f.cvss_score}</td></tr>` : ""}
        ${f.cwe ? `<tr><td style="padding:3px 12px 3px 0;color:#666">CWE</td><td>${escapeHtml(f.cwe)}</td></tr>` : ""}
        <tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">置信度</td><td>${escapeHtml(f.confidence ?? "-")}</td></tr>
        <tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">漏洞类型</td><td>${escapeHtml(f.vuln_type ?? "-")}</td></tr>
        <tr><td style="padding:3px 12px 3px 0;color:#666">复核结论</td><td>${escapeHtml(`${status} / ${sourceStatus} / ${action}`)}</td></tr>
        <tr><td style="padding:3px 12px 3px 0;color:#666;white-space:nowrap">位置</td><td><code>${escapeHtml(f.file_path ?? "-")}${f.line_number ? `:${f.line_number}` : ""}</code></td></tr>
        ${f.agent_source ? `<tr><td style="padding:3px 12px 3px 0;color:#666">发现Agent</td><td>${escapeHtml(f.agent_source)}</td></tr>` : ""}
      </table>
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">一、漏洞描述</h4><p style="white-space:pre-wrap;margin:0">${escapeHtml(f.description || "报告阶段未记录漏洞描述，需回看原始 finding。")}</p></section>
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">二、漏洞根因</h4><p style="white-space:pre-wrap;margin:0">${escapeHtml(rootCause)}</p></section>
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">三、攻击者利用方法</h4><p style="white-space:pre-wrap;margin:0">${escapeHtml(exploitMethod)}</p></section>
      ${buildSinkChainHtml(steps, f, verification)}
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">六、PoC</h4>${f.poc ? `<pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;overflow-x:auto;font-size:0.85em;white-space:pre-wrap">${escapeHtml(f.poc)}</pre>` : `<p><em>报告阶段未记录 PoC，需结合上述攻击者利用方法补充最小复现步骤。</em></p>`}</section>
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">七、修复提示</h4><p>${escapeHtml(fixBrief)}</p></section>
      <section style="margin:12px 0"><h4 style="margin:0 0 6px">八、参考</h4><ul><li>${escapeHtml(f.cwe || "暂无 CWE 记录")}</li></ul></section>
    </article>`;
  }

  let attackHtml = "";
  if (attackChains.length) {
    attackHtml = `<h2 style="border-bottom:2px solid #333;padding-bottom:8px;margin-top:40px">攻击链分析</h2>`;
    for (const chain of attackChains) {
      const steps = chainSteps.filter(s => s.chain_id === chain.id);
      const stepsHtml = steps.map(s => {
        const f = findings.find(x => x.id === s.finding_id);
        return `<li><strong>[${f?._vid ?? s.finding_id}]</strong> ${escapeHtml(f?.title ?? "Unknown")}${s.link_desc ? ` → <em>${escapeHtml(s.link_desc)}</em>` : ""}</li>`;
      }).join("\n");
      attackHtml += `
      <div style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:20px;margin:16px 0">
        <h3 style="margin:0 0 8px">${escapeHtml(chain.chain_title)} ${severityBadge(chain.combined_severity)}</h3>
        <p>${escapeHtml(chain.description)}</p>
        ${steps.length ? `<ol style="margin:8px 0">${stepsHtml}</ol>` : ""}
      </div>`;
    }
  }

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>安全审计报告 — ${escapeHtml(projectName)}</title>
  <style>
    body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; max-width:1100px; margin:0 auto; padding:24px; background:#f8f9fa; color:#212121; }
    h1 { color:#1a1a2e; } h2 { color:#16213e; } h3 { color:#0f3460; }
    code { background:#f0f0f0; padding:1px 5px; border-radius:3px; font-size:0.9em; }
    details summary:hover { opacity:0.8; }
    @media print { body { background:#fff; } }
  </style>
</head>
<body>
  <h1>安全审计报告</h1>
  <table style="font-size:0.95em;margin-bottom:24px">
    <tr><td style="padding:3px 16px 3px 0;color:#666">项目</td><td><strong>${escapeHtml(projectName)}</strong></td></tr>
    <tr><td style="color:#666">路径</td><td><code>${escapeHtml(project.path ?? "-")}</code></td></tr>
    <tr><td style="color:#666">技术栈</td><td>${escapeHtml([project.language, project.framework].filter(Boolean).join(" / ") || "-")}</td></tr>
    <tr><td style="color:#666">审计模式</td><td>${escapeHtml(session.mode ?? "-")}</td></tr>
    <tr><td style="color:#666">审计时间</td><td>${escapeHtml(session.started_at)}</td></tr>
    <tr><td style="color:#666">报告生成</td><td>${date}</td></tr>
    ${session.notes ? `<tr><td style="color:#666">备注</td><td>${escapeHtml(session.notes)}</td></tr>` : ""}
  </table>

  <h2>执行摘要</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0">
    ${statCards}
    <div style="background:#37474f;color:#fff;padding:16px 24px;border-radius:8px;text-align:center;min-width:100px">
      <div style="font-size:2em;font-weight:bold">${findings.length}</div>
      <div style="font-size:0.9em;margin-top:4px">合计</div>
    </div>
  </div>

  ${buildVerificationSummaryHtml(orderedFindings, sinkMap, verificationMap)}

  <h2 style="border-bottom:2px solid #333;padding-bottom:8px;margin-top:40px">漏洞详情</h2>
  ${findingsHtml}
  ${attackHtml}

  <footer style="margin-top:48px;padding-top:16px;border-top:1px solid #ddd;color:#888;font-size:0.85em">
    Generated by audit-db plugin · ${date}
  </footer>
</body>
</html>`;
}

const auditGenerateReport = tool({
  description: "Generate Markdown and HTML audit reports from the database for a given session. Returns the paths of the generated files.",
  args: {
    session_id: tool.schema.number().describe("Session ID to generate report for"),
    output_dir: tool.schema.string().optional().describe("Output directory for report files. Defaults to {project_path}/audit-reports/"),
    allow_unverified: tool.schema.boolean().optional().describe("Allow generating a draft report when some findings have no verification. Defaults to false."),
  },
  async execute(args, ctx) {
    const db = getDb();

    const session = db.query("SELECT * FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) { db.close(); return JSON.stringify({ error: `Session ${args.session_id} not found` }); }

    const project = db.query("SELECT * FROM projects WHERE id=?").get(session.project_id);

    const findings = db.query(
      `SELECT * FROM findings WHERE session_id=? ORDER BY
         CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         id`
    ).all(args.session_id);

    const sinkMap = {};
    for (const f of findings) {
      sinkMap[f.id] = db.query(
        "SELECT * FROM sink_chains WHERE finding_id=? ORDER BY step_order"
      ).all(f.id);
    }

    const verificationMap = {};
    if (findings.length) {
      const verificationRows = db.query(
        `SELECT * FROM finding_verifications
         WHERE finding_id IN (${findings.map(() => "?").join(",")})
         ORDER BY finding_id, id`
      ).all(...findings.map(f => f.id));
      for (const row of verificationRows) verificationMap[row.finding_id] = row;
    }

    const missingVerificationIds = findings
      .filter(f => !verificationMap[f.id])
      .map(f => f.id);
    if (missingVerificationIds.length && !args.allow_unverified) {
      db.close();
      return JSON.stringify({
        error: "missing_verifications",
        message: "Final report requires every finding to be verified and written back before generation.",
        findings: findings.length,
        verified: findings.length - missingVerificationIds.length,
        missing_finding_ids: missingVerificationIds,
      });
    }

    const attackChains = db.query(
      "SELECT * FROM attack_chains WHERE session_id=? ORDER BY id"
    ).all(args.session_id);

    const chainSteps = attackChains.length
      ? db.query(
          `SELECT * FROM attack_chain_steps WHERE chain_id IN (${attackChains.map(() => "?").join(",")}) ORDER BY chain_id, step_order`
        ).all(...attackChains.map(c => c.id))
      : [];

    db.close();

    // Determine output directory
    const outDir = args.output_dir
      ?? (project.path ? join(project.path, "audit-reports") : join(ctx.directory, "audit-reports"));
    mkdirSync(outDir, { recursive: true });

    const slug = `${reportFileProjectName(project)}-${args.session_id}-${reportTimestamp()}`;
    const mdPath   = join(outDir, `${slug}.md`);
    const htmlPath = join(outDir, `${slug}.html`);

    const md   = generateMarkdown(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap);
    const html = generateHtml(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap);

    writeFileSync(mdPath,   md,   "utf8");
    writeFileSync(htmlPath, html, "utf8");

    return JSON.stringify({
      markdown: mdPath,
      html:     htmlPath,
      findings: findings.length,
      critical: findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === "Critical").length,
      high:     findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === "High").length,
    });
  },
});

// ─── Plugin export ────────────────────────────────────────────────────────────

export default async (_ctx) => ({
  tool: {
    audit_init_session:    auditInitSession,
    audit_save_finding:    auditSaveFinding,
    audit_save_sink_chain: auditSaveSinkChain,
    audit_save_verification: auditSaveVerification,
    audit_update_finding_after_verification: auditUpdateFindingAfterVerification,
    audit_get_findings_for_verification: auditGetFindingsForVerification,
    audit_save_attack_chain: auditSaveAttackChain,
    audit_complete_session: auditCompleteSession,
    audit_list_sessions:   auditListSessions,
    audit_generate_report: auditGenerateReport,
  },
});
