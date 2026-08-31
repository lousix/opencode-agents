import { tool } from "@opencode-ai/plugin";
import { Database } from "bun:sqlite";
import { homedir } from "os";
import { join, dirname, basename, relative } from "path";
import { mkdirSync, existsSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";

// DB stored at ~/.opencode/audit.db — shared across all projects
const DB_PATH = String(process.env.OPENCODE_AUDIT_DB_PATH ?? "").trim()
  || join(homedir(), ".opencode", "audit.db");

function getDb() {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const db = new Database(DB_PATH);
  db.run("PRAGMA journal_mode=WAL");
  db.run("PRAGMA foreign_keys=ON");
  initSchema(db);
  return db;
}

function ensureColumn(db, table, column, definition) {
  const columns = db.query(`PRAGMA table_info(${table})`).all();
  if (!columns.some((item) => item.name === column)) {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
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
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  // SQLite cannot add a column with CURRENT_TIMESTAMP as a non-constant
  // default on older databases, so migrate it in two safe steps.
  ensureColumn(db, "findings", "updated_at", "DATETIME");
  db.run("UPDATE findings SET updated_at=COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL");

  db.run(`CREATE TABLE IF NOT EXISTS sink_chains (
    id           INTEGER PRIMARY KEY,
    finding_id   INTEGER REFERENCES findings(id),
    step_order   INTEGER,
    step_type    TEXT,
    file_path    TEXT,
    line_number  INTEGER,
    function_name TEXT,
    context_start_line INTEGER,
    context_end_line   INTEGER,
    code_snippet TEXT,
    notes        TEXT
  )`);
  ensureColumn(db, "sink_chains", "function_name", "TEXT");
  ensureColumn(db, "sink_chains", "context_start_line", "INTEGER");
  ensureColumn(db, "sink_chains", "context_end_line", "INTEGER");

  db.run(`CREATE TABLE IF NOT EXISTS sink_candidates (
    id            INTEGER PRIMARY KEY,
    session_id    INTEGER REFERENCES audit_sessions(id),
    finding_id    INTEGER REFERENCES findings(id),
    dimension     TEXT,
    agent_source  TEXT,
    round_number  INTEGER DEFAULT 1,
    sink_type     TEXT,
    pattern       TEXT,
    file_path     TEXT,
    line_number   INTEGER,
    code_snippet  TEXT,
    status        TEXT,
    reason        TEXT,
    evidence      TEXT,
    risk          TEXT,
    path_status   TEXT,
    traced_depth  INTEGER,
    ledger_file   TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_sink_candidates_session_status
          ON sink_candidates(session_id, status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_sink_candidates_session_dimension
          ON sink_candidates(session_id, dimension)`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_agent_runs (
    id               INTEGER PRIMARY KEY,
    session_id       INTEGER REFERENCES audit_sessions(id),
    dimension        TEXT NOT NULL,
    agent_source     TEXT NOT NULL,
    round_number     INTEGER DEFAULT 1,
    runtime_handle   TEXT,
    status           TEXT DEFAULT 'QUEUED',
    skip_code        TEXT,
    status_reason    TEXT,
    current_phase    TEXT,
    started_at       DATETIME,
    heartbeat_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    interrupted_at   DATETIME,
    resumed_at       DATETIME,
    completed_at     DATETIME,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, dimension, round_number)
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_agent_runs_session_status
          ON audit_agent_runs(session_id, status)`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_candidates (
    id             INTEGER PRIMARY KEY,
    session_id     INTEGER REFERENCES audit_sessions(id),
    finding_id     INTEGER REFERENCES findings(id),
    dimension      TEXT,
    agent_source   TEXT,
    round_number   INTEGER DEFAULT 1,
    candidate_kind TEXT,
    rule_id        TEXT,
    candidate_type TEXT,
    evidence_type  TEXT,
    file_path      TEXT,
    line_number    INTEGER,
    code_snippet   TEXT,
    status         TEXT,
    reason         TEXT,
    evidence       TEXT,
    risk           TEXT,
    path_status    TEXT,
    traced_depth   INTEGER,
    agent_run_id   INTEGER REFERENCES audit_agent_runs(id),
    candidate_key  TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_candidates_session_status
          ON audit_candidates(session_id, status)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_candidates_session_kind
          ON audit_candidates(session_id, candidate_kind)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_candidates_session_dimension
          ON audit_candidates(session_id, dimension)`);

  // Existing databases predate resumable agent runs and idempotent candidates.
  ensureColumn(db, "audit_candidates", "agent_run_id", "INTEGER REFERENCES audit_agent_runs(id)");
  ensureColumn(db, "audit_candidates", "candidate_key", "TEXT");
  // SQLite permits multiple NULLs in a UNIQUE index; keep the index non-partial so
  // the UPSERT conflict target matches it exactly on every supported SQLite build.
  db.run("DROP INDEX IF EXISTS idx_audit_candidates_stable_key");
  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_candidates_stable_key
          ON audit_candidates(session_id, dimension, candidate_key)`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_agent_checkpoints (
    id                 INTEGER PRIMARY KEY,
    agent_run_id       INTEGER REFERENCES audit_agent_runs(id),
    checkpoint_seq     INTEGER NOT NULL,
    current_phase      TEXT,
    search_cursor      TEXT,
    remaining_work     TEXT,
    files_read         TEXT,
    grep_done          TEXT,
    open_candidate_ids TEXT,
    active_trace       TEXT,
    tool_usage         TEXT,
    checkpoint_reason  TEXT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(agent_run_id, checkpoint_seq)
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

  db.run(`CREATE TABLE IF NOT EXISTS finding_detail_runs (
    id               INTEGER PRIMARY KEY,
    session_id       INTEGER REFERENCES audit_sessions(id),
    finding_id       INTEGER NOT NULL REFERENCES findings(id),
    agent_source     TEXT NOT NULL DEFAULT 'audit-verification',
    runtime_handle   TEXT,
    status           TEXT NOT NULL DEFAULT 'QUEUED',
    current_phase    TEXT,
    status_reason    TEXT,
    started_at       DATETIME,
    heartbeat_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    interrupted_at   DATETIME,
    resumed_at       DATETIME,
    completed_at     DATETIME,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id)
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_finding_detail_runs_session_status
          ON finding_detail_runs(session_id, status)`);

  db.run(`CREATE TABLE IF NOT EXISTS finding_detail_checkpoints (
    id                 INTEGER PRIMARY KEY,
    detail_run_id      INTEGER NOT NULL REFERENCES finding_detail_runs(id),
    checkpoint_seq     INTEGER NOT NULL,
    current_phase      TEXT,
    search_cursor      TEXT,
    remaining_work     TEXT,
    files_read         TEXT,
    active_trace       TEXT,
    tool_usage         TEXT,
    checkpoint_reason  TEXT,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(detail_run_id, checkpoint_seq)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS finding_report_details (
    finding_id                INTEGER PRIMARY KEY REFERENCES findings(id),
    report_title              TEXT NOT NULL,
    component_name            TEXT,
    product_impact            TEXT NOT NULL,
    affected_assets           TEXT NOT NULL DEFAULT '[]',
    root_cause                TEXT NOT NULL,
    attacker_profile          TEXT NOT NULL,
    exploit_difficulty        TEXT NOT NULL,
    preconditions             TEXT NOT NULL DEFAULT '[]',
    attack_steps              TEXT NOT NULL DEFAULT '[]',
    exploit_limitations       TEXT NOT NULL DEFAULT '[]',
    cia_impact                TEXT NOT NULL DEFAULT '{}',
    affected_scope            TEXT NOT NULL,
    poc_explanation           TEXT,
    expected_result           TEXT,
    poc_type                  TEXT,
    poc_validation_status     TEXT,
    poc_language              TEXT,
    poc_source                TEXT,
    poc_setup_commands        TEXT NOT NULL DEFAULT '[]',
    poc_build_commands        TEXT NOT NULL DEFAULT '[]',
    poc_run_commands          TEXT NOT NULL DEFAULT '[]',
    poc_expected_output       TEXT,
    poc_observed_output       TEXT,
    poc_negative_control_commands TEXT NOT NULL DEFAULT '[]',
    poc_negative_control_expected TEXT,
    poc_cleanup_commands      TEXT NOT NULL DEFAULT '[]',
    poc_fixed_result          TEXT,
    poc_safety_notes          TEXT,
    poc_execution_limitations TEXT,
    verification_steps        TEXT NOT NULL DEFAULT '[]',
    immediate_mitigations     TEXT NOT NULL DEFAULT '[]',
    required_fixes            TEXT NOT NULL DEFAULT '[]',
    acceptance_criteria       TEXT NOT NULL DEFAULT '[]',
    regression_tests          TEXT NOT NULL DEFAULT '[]',
    related_locations         TEXT NOT NULL DEFAULT '[]',
    related_finding_ids       TEXT NOT NULL DEFAULT '[]',
    evidence_limitations      TEXT,
    language                  TEXT NOT NULL DEFAULT 'zh-CN',
    content_version           INTEGER NOT NULL DEFAULT 1,
    created_at                DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  ensureColumn(db, "finding_report_details", "component_name", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_type", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_validation_status", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_language", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_source", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_setup_commands", "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "finding_report_details", "poc_build_commands", "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "finding_report_details", "poc_run_commands", "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "finding_report_details", "poc_expected_output", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_observed_output", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_negative_control_commands", "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "finding_report_details", "poc_negative_control_expected", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_cleanup_commands", "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn(db, "finding_report_details", "poc_fixed_result", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_safety_notes", "TEXT");
  ensureColumn(db, "finding_report_details", "poc_execution_limitations", "TEXT");

  db.run(`CREATE TABLE IF NOT EXISTS finding_report_artifacts (
    id                    INTEGER PRIMARY KEY,
    finding_id            INTEGER NOT NULL REFERENCES findings(id),
    content_version       INTEGER NOT NULL,
    content_hash          TEXT NOT NULL,
    markdown_path         TEXT NOT NULL,
    language_status       TEXT NOT NULL,
    generated_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, content_version)
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

const SINK_CANDIDATE_STATUSES = new Set([
  "TRACED_VULN",
  "TRACED_SAFE",
  "TRACED_SANITIZED",
  "TRACED_NO_SOURCE",
  "FALSE_POSITIVE",
  "EXCLUDED_TEST",
  "EXCLUDED_VENDOR",
  "UNREACHABLE",
  "OPEN",
  "TIMEOUT",
]);

const SINK_CANDIDATE_OPEN_STATUSES = new Set(["OPEN", "TIMEOUT"]);

function normalizeSinkCandidateStatus(value) {
  const status = String(value ?? "OPEN").trim().toUpperCase();
  return SINK_CANDIDATE_STATUSES.has(status) ? status : "OPEN";
}

function normalizePathStatus(value) {
  const status = String(value ?? "UNKNOWN").trim().toUpperCase();
  if (["COMPLETE", "PARTIAL", "NOT_REQUIRED", "UNKNOWN"].includes(status)) return status;
  return "UNKNOWN";
}

function stableCandidateKey(raw, defaults = {}) {
  if (raw?.candidate_key) return String(raw.candidate_key).trim();
  const canonical = [
    String(raw?.candidate_kind ?? defaults.candidate_kind ?? "UNKNOWN").trim().toUpperCase(),
    String(raw?.rule_id ?? raw?.candidate_type ?? raw?.sink_type ?? "UNKNOWN").trim().toUpperCase(),
    String(raw?.file_path ?? "").trim().replaceAll("\\", "/"),
    String(raw?.line_number ?? "NA").trim(),
    String(raw?.symbol ?? raw?.pattern ?? "").trim(),
  ].join("|");
  return createHash("sha256").update(canonical).digest("hex").slice(0, 32);
}

function requireJsonText(value, fieldName, fallback = "[]") {
  const text = value === undefined || value === null || value === "" ? fallback : String(value);
  try {
    JSON.parse(text);
    return { value: text };
  } catch {
    return { error: `${fieldName} must be valid JSON` };
  }
}

const HAN_TEXT = /[\u3400-\u9fff]/;
const POC_TYPES = new Set(["EXECUTABLE_POC", "STATIC_REPRO", "REGRESSION_TEST", "MANUAL_ONLY", "NOT_REPRODUCED"]);
const POC_VALIDATION_STATUSES = new Set(["NOT_RUN", "SYNTAX_CHECKED", "BUILT", "EXECUTED", "FAILED", "BLOCKED"]);

function normalizedEnum(value, allowed, fallback = "") {
  const normalized = String(value ?? fallback).trim().toUpperCase();
  return allowed.has(normalized) ? normalized : "";
}

function nonEmptyStringArray(value) {
  return Array.isArray(value) && value.length > 0
    && value.every((item) => typeof item === "string" && item.trim());
}

function containsLocalAbsolutePath(value) {
  return /(?:^|[\s"'`])(?:\/Users\/|\/home\/[^/\s]+\/|\/private\/tmp\/|\/tmp\/|[A-Za-z]:\\Users\\|file:\/\/)/m.test(String(value ?? ""));
}

function containsPocPlaceholder(value) {
  return /(?:\bTODO\b|\bFIXME\b|\bPLACEHOLDER\b|\bFILL[_ -]?ME\b|\bYOUR[_ -][A-Z_]+\b|<[^>]*(?:填入|替换|placeholder|your)[^>]*>|伪代码|占位符)/i.test(String(value ?? ""));
}

function sourceIsOnlyComments(value) {
  const lines = String(value ?? "").split("\n").map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return true;
  return lines.every((line) => /^(?:\/\/|\/\*|\*|\*\/|#|--)/.test(line));
}

function memorySafetyFinding(finding) {
  const text = `${finding?.vuln_type ?? ""} ${finding?.title ?? ""} ${finding?.cwe ?? ""}`;
  return /(?:越界|缓冲区|内存泄漏|释放后使用|重复释放|空指针|整数溢出|out[- ]of[- ]bounds|buffer overflow|use[- ]after[- ]free|double free|null pointer|integer overflow|CWE-(?:119|120|121|122|125|126|127|190|191|415|416|476|680|787|788|789))/i.test(text);
}

function validatePocDetails(args, normalized, finding, verification) {
  const pocType = normalizedEnum(args.poc_type, POC_TYPES);
  const validationStatus = normalizedEnum(args.poc_validation_status, POC_VALIDATION_STATUSES);
  if (!pocType) return { error: "poc_type must be EXECUTABLE_POC, STATIC_REPRO, REGRESSION_TEST, MANUAL_ONLY, or NOT_REPRODUCED" };
  if (!validationStatus) return { error: "poc_validation_status must be NOT_RUN, SYNTAX_CHECKED, BUILT, EXECUTED, FAILED, or BLOCKED" };

  const source = String(args.poc_source ?? "").trim();
  const language = String(args.poc_language ?? "").trim().toLowerCase();
  const expected = String(args.poc_expected_output ?? args.expected_result ?? "").trim();
  const observed = String(args.poc_observed_output ?? "").trim();
  const negativeExpected = String(args.poc_negative_control_expected ?? "").trim();
  const fixedResult = String(args.poc_fixed_result ?? "").trim();
  const safetyNotes = String(args.poc_safety_notes ?? "").trim();
  const limitations = String(args.poc_execution_limitations ?? "").trim();
  const runCommands = normalized.poc_run_commands.parsed;
  const negativeCommands = normalized.poc_negative_control_commands.parsed;
  const allPortableMaterial = [source, ...normalized.poc_setup_commands.parsed,
    ...normalized.poc_build_commands.parsed, ...runCommands,
    ...negativeCommands, ...normalized.poc_cleanup_commands.parsed,
    expected, observed, negativeExpected, fixedResult].join("\n");

  for (const field of ["poc_setup_commands", "poc_build_commands", "poc_run_commands",
    "poc_negative_control_commands", "poc_cleanup_commands"]) {
    if (!normalized[field].parsed.every((item) => typeof item === "string" && item.trim())) {
      return { error: `${field} must contain only non-empty command strings` };
    }
  }

  if (containsLocalAbsolutePath(allPortableMaterial)) {
    return { error: "PoC material must use repository/report-relative paths and must not contain local absolute paths" };
  }
  if (containsPocPlaceholder(allPortableMaterial)) {
    return { error: "PoC material contains placeholder or pseudocode markers" };
  }
  if (source && !/^[a-z0-9_+.#-]+$/i.test(language)) {
    return { error: "poc_language is required and must be a valid Markdown fence language when poc_source is present" };
  }
  if (["EXECUTABLE_POC", "REGRESSION_TEST"].includes(pocType)) {
    if (!source) return { error: `${pocType} requires complete poc_source embedded in the report` };
    if (sourceIsOnlyComments(source)) return { error: `${pocType} source must contain executable code, not comments only` };
    if (!nonEmptyStringArray(runCommands)) return { error: `${pocType} requires executable poc_run_commands` };
    if (!expected) return { error: `${pocType} requires poc_expected_output` };
    if (!nonEmptyStringArray(negativeCommands) || !negativeExpected) {
      return { error: `${pocType} requires a negative control command and its expected result` };
    }
    if (!safetyNotes) return { error: `${pocType} requires Chinese poc_safety_notes` };
  }
  if (pocType === "STATIC_REPRO") {
    if (!nonEmptyStringArray(runCommands)) return { error: "STATIC_REPRO requires executable verification commands" };
    if (!expected) return { error: "STATIC_REPRO requires poc_expected_output" };
    if (!nonEmptyStringArray(negativeCommands) || !negativeExpected) {
      return { error: "STATIC_REPRO requires a negative control command and its expected result" };
    }
  }
  if (pocType === "REGRESSION_TEST" && !fixedResult) {
    return { error: "REGRESSION_TEST requires poc_fixed_result describing the fixed-pass condition" };
  }
  if (pocType === "MANUAL_ONLY" && !limitations) {
    return { error: "MANUAL_ONLY requires Chinese poc_execution_limitations explaining why automation is unavailable" };
  }
  if (pocType === "NOT_REPRODUCED" && !limitations) {
    return { error: "NOT_REPRODUCED requires Chinese poc_execution_limitations describing the evidence gap" };
  }
  if (["EXECUTED", "FAILED"].includes(validationStatus) && !observed) {
    return { error: `${validationStatus} requires poc_observed_output captured from the actual run` };
  }
  if (!["EXECUTED", "FAILED"].includes(validationStatus) && observed) {
    return { error: "poc_observed_output is allowed only when validation status is EXECUTED or FAILED" };
  }
  if (pocType === "NOT_REPRODUCED" && !["NOT_RUN", "BLOCKED"].includes(validationStatus)) {
    return { error: "NOT_REPRODUCED may only use NOT_RUN or BLOCKED validation status" };
  }
  if (["VERIFIED"].includes(String(verification?.verdict ?? "").toUpperCase())
      && String(verification?.exploitability ?? "").toUpperCase() === "PRACTICAL"
      && ["MANUAL_ONLY", "NOT_REPRODUCED"].includes(pocType)) {
    return { error: "VERIFIED and PRACTICAL findings require executable PoC, static reproduction, or regression-test evidence" };
  }
  if (memorySafetyFinding(finding) && ["EXECUTABLE_POC", "REGRESSION_TEST"].includes(pocType)
      && ["c", "cpp", "c++"].includes(language)) {
    const buildAndRun = [...normalized.poc_build_commands.parsed, ...runCommands].join(" ");
    if (!/(?:fsanitize=(?:address|undefined)|asan|ubsan|valgrind)/i.test(buildAndRun)) {
      return { error: "C/C++ memory-safety PoC or regression test requires ASAN/UBSAN/Valgrind instrumentation in build/run commands" };
    }
  }
  return { pocType, validationStatus, expected };
}

function parseJsonField(value, fieldName, fallback, expectedType) {
  const normalized = requireJsonText(value, fieldName, JSON.stringify(fallback));
  if (normalized.error) return normalized;
  const parsed = JSON.parse(normalized.value);
  const valid = expectedType === "array"
    ? Array.isArray(parsed)
    : expectedType === "object"
      ? parsed && typeof parsed === "object" && !Array.isArray(parsed)
      : true;
  return valid
    ? { value: normalized.value, parsed }
    : { error: `${fieldName} must be a JSON ${expectedType}` };
}

function looksTechnicalOnly(value) {
  const text = String(value ?? "").trim();
  if (!text) return true;
  return /^(?:P[0-2]|CWE-\d+|CVE-\d{4}-\d+|D10|D[1-9]|[A-Z][A-Z0-9_-]*|https?:\/\/\S+|[A-Za-z0-9_@./\\:#?=&%+<>()[\]{}'"`*-]+)$/i.test(text);
}

function chineseTextError(fieldName, value, required = true) {
  const text = String(value ?? "").trim();
  if (!text) return required ? `${fieldName} is required` : null;
  if (!HAN_TEXT.test(text)) {
    return `${fieldName} must use Chinese natural-language prose`;
  }
  return null;
}

function chineseJsonError(fieldName, value) {
  const visit = (node, path) => {
    if (typeof node === "string") {
      const text = node.trim();
      if (text && !HAN_TEXT.test(text) && !looksTechnicalOnly(text)) {
        return `${path} must use Chinese natural-language prose`;
      }
      return null;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const error = visit(node[i], `${path}[${i}]`);
        if (error) return error;
      }
      return null;
    }
    if (node && typeof node === "object") {
      for (const [key, child] of Object.entries(node)) {
        const error = visit(child, `${path}.${key}`);
        if (error) return error;
      }
    }
    return null;
  };
  return visit(value, fieldName);
}

function parseStoredJson(value, fallback) {
  try {
    return value === undefined || value === null || value === "" ? fallback : JSON.parse(value);
  } catch {
    return fallback;
  }
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

function normalizeSeverity(value) {
  const severity = String(value ?? "").trim().toLowerCase();
  return SEVERITY_ORDER.find((s) => s.toLowerCase() === severity) ?? "Info";
}

function firstPresent(obj, keys) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== undefined && obj[key] !== null) {
      return obj[key];
    }
  }
  return undefined;
}

function stringifyStepValue(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === "string") return value.trim() || null;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function parseLineNumber(value) {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  if (Number.isFinite(n)) return Math.trunc(n);
  const match = String(value).match(/\d+/);
  return match ? Number(match[0]) : null;
}

function extractLocation(value) {
  const text = stringifyStepValue(value);
  if (!text) return {};
  const match = text.match(/((?:[A-Za-z]:)?[A-Za-z0-9_@./\\-]+):(\d+)/);
  if (!match) return {};
  return { file_path: match[1], line_number: Number(match[2]) };
}

function inferStepType(value, index = 0, total = 1) {
  const text = String(value ?? "").trim();
  if (/source|污点源|数据源|入口|入参|请求|参数|header|cookie|body|webhook|mq|rpc/i.test(text)) return "Source";
  if (/sink|汇聚|危险|执行|命令|sql|ssrf|fileutil|runtime|curl|clone|delete|write|read/i.test(text)) return "Sink";
  if (/saniti[sz]er|filter|validate|escape|check|allowlist|净化|过滤|校验|检查|白名单|黑名单|权限/i.test(text)) return "Sanitizer";
  if (/transform|propagat|build|convert|process|concat|assign|parse|转换|传播|拼接|构造|处理|赋值|中间/i.test(text)) return "Transform";
  if (total <= 1) return "Sink";
  if (index === 0) return "Source";
  if (index === total - 1) return "Sink";
  return "Transform";
}

function normalizeStepType(type) {
  const t = String(type ?? "").trim();
  if (!t) return "Step";
  if (/source|entry|input|request|param|污点源|数据源|入口|入参|请求|参数/i.test(t)) return "Source";
  if (/sink|danger|execute|execution|callsite|汇聚|危险|执行点|落点/i.test(t)) return "Sink";
  if (/saniti[sz]er|filter|validat|escape|check|allowlist|净化|过滤|校验|检查|白名单|黑名单|权限/i.test(t)) return "Sanitizer";
  if (/transform|propagat|build|convert|process|concat|assign|parse|转换|传播|拼接|构造|处理|赋值|中间/i.test(t)) return "Transform";
  return t;
}

function parseStringStep(raw, index, total) {
  const text = stringifyStepValue(raw) ?? "";
  const loc = extractLocation(text);
  const parts = text.split("|").map((p) => p.trim()).filter(Boolean);
  const codeish = parts.find((p) => /[;{}=()]|@\w+|public |private |return |new |\.exec|\.query|curl |git /i.test(p));
  const stageText = parts[0] ?? text;
  return {
    step_type: inferStepType(stageText, index, total),
    file_path: loc.file_path ?? null,
    line_number: loc.line_number ?? null,
    function_name: null,
    context_start_line: null,
    context_end_line: null,
    code_snippet: codeish && codeish !== stageText ? codeish : null,
    notes: text || null,
  };
}

function parseObjectStep(raw, index, total) {
  const entries = Object.entries(raw).filter(([, value]) => value !== undefined && value !== null && value !== "");
  let typeValue = firstPresent(raw, [
    "step_type", "stepType", "type", "stage", "kind", "role", "node_type", "nodeType",
    "phase", "阶段", "类型", "节点类型",
  ]);
  let singleValue;
  if (!typeValue && entries.length === 1) {
    typeValue = entries[0][0];
    singleValue = entries[0][1];
  }

  const locationValue = firstPresent(raw, [
    "location", "loc", "position", "位置", "source", "sink",
  ]) ?? singleValue;
  const loc = extractLocation(locationValue);
  const fileValue = firstPresent(raw, [
    "file_path", "filePath", "filepath", "file", "path", "文件", "路径",
  ]);
  const fileLoc = extractLocation(fileValue);
  const lineValue = firstPresent(raw, [
    "line_number", "lineNumber", "line", "lineno", "行号",
  ]);
  const functionValue = firstPresent(raw, [
    "function_name", "functionName", "function", "method_name", "methodName", "method",
    "symbol", "symbol_name", "symbolName", "函数", "函数名", "方法", "方法名",
  ]);
  const contextStartValue = firstPresent(raw, [
    "context_start_line", "contextStartLine", "snippet_start_line", "snippetStartLine", "代码起始行",
  ]);
  const contextEndValue = firstPresent(raw, [
    "context_end_line", "contextEndLine", "snippet_end_line", "snippetEndLine", "代码结束行",
  ]);
  const codeValue = firstPresent(raw, [
    "code_snippet", "codeSnippet", "snippet", "code", "evidence", "key_code",
    "vuln_code", "代码", "证据", "关键代码",
  ]);
  const notesValue = firstPresent(raw, [
    "notes", "note", "description", "reason", "judgment", "summary", "处理",
    "说明", "判断", "备注", "安全判断",
  ]) ?? singleValue;

  const typeText = [
    stringifyStepValue(typeValue),
    stringifyStepValue(locationValue),
    stringifyStepValue(notesValue),
    stringifyStepValue(codeValue),
  ].filter(Boolean).join(" ");
  const normalizedType = normalizeStepType(typeValue);

  return {
    step_type: normalizedType === "Step" ? inferStepType(typeText, index, total) : normalizedType,
    file_path: fileLoc.file_path ?? stringifyStepValue(fileValue) ?? loc.file_path ?? null,
    line_number: parseLineNumber(lineValue) ?? loc.line_number ?? fileLoc.line_number ?? null,
    function_name: stringifyStepValue(functionValue),
    context_start_line: parseLineNumber(contextStartValue),
    context_end_line: parseLineNumber(contextEndValue),
    code_snippet: stringifyStepValue(codeValue),
    notes: stringifyStepValue(notesValue),
  };
}

function hasStepEvidence(step) {
  return Boolean(
    step?.file_path ||
    (step?.line_number !== null && step?.line_number !== undefined) ||
    step?.function_name ||
    step?.code_snippet ||
    step?.notes
  );
}

function normalizeSinkChainSteps(rawSteps) {
  if (!Array.isArray(rawSteps)) {
    return { error: "steps must be a JSON array" };
  }
  if (!rawSteps.length) {
    return { error: "steps must not be empty; omit sink_chain_steps to keep the existing chain" };
  }

  const normalized = rawSteps.map((raw, index) => {
    if (typeof raw === "string" || typeof raw === "number" || typeof raw === "boolean") {
      return parseStringStep(raw, index, rawSteps.length);
    }
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      return parseObjectStep(raw, index, rawSteps.length);
    }
    return {
      step_type: inferStepType("", index, rawSteps.length),
      file_path: null,
      line_number: null,
      function_name: null,
      context_start_line: null,
      context_end_line: null,
      code_snippet: null,
      notes: stringifyStepValue(raw),
    };
  }).filter(hasStepEvidence);

  if (!normalized.length) {
    return {
      error: "steps contained no usable evidence; each step needs file_path/location, line_number, function_name, code_snippet, or notes",
    };
  }

  return { steps: normalized, discarded: rawSteps.length - normalized.length };
}

function reportableSinkSteps(steps = []) {
  const evidenceSteps = steps.filter(hasStepEvidence);
  return evidenceSteps.map((step, index) => ({
    ...step,
    step_type: normalizeStepType(step.step_type) === "Step"
      ? inferStepType(`${step.notes ?? ""} ${step.code_snippet ?? ""}`, index, evidenceSteps.length)
      : normalizeStepType(step.step_type),
  }));
}

function chainEvidenceStatus(steps = []) {
  const reportable = reportableSinkSteps(steps);
  const hasSource = reportable.some((s) => normalizeStepType(s.step_type) === "Source");
  const hasSink = reportable.some((s) => normalizeStepType(s.step_type) === "Sink");
  return {
    steps: reportable,
    hasEvidence: reportable.length > 0,
    hasSource,
    hasSink,
    complete: reportable.length > 0 && hasSource && hasSink,
  };
}

function codeContextLineCount(snippet) {
  return String(snippet ?? "").split(/\r?\n/).filter((line) => line.trim()).length;
}

function detailedEvidenceQuality(steps = [], severity = "Info") {
  const reportable = reportableSinkSteps(steps);
  if (!["Critical", "High", "Medium"].includes(normalizeSeverity(severity))) {
    return { complete: true, issues: [] };
  }
  const issues = [];
  for (const [index, step] of reportable.entries()) {
    const type = normalizeStepType(step.step_type);
    if (!["Source", "Sink", "Transform", "Sanitizer"].includes(type)) continue;
    const location = stepLocation(step);
    if (["Source", "Sink"].includes(type) && !String(step.function_name ?? "").trim()) {
      issues.push({ step: index + 1, type, location, reason: "缺少相关函数名称" });
    }
    const minimumLines = ["Source", "Sink"].includes(type) ? 8 : 5;
    const actualLines = codeContextLineCount(step.code_snippet);
    if (actualLines < minimumLines) {
      issues.push({ step: index + 1, type, location, function_name: step.function_name ?? null,
        reason: `代码上下文不足，至少需要 ${minimumLines} 行非空代码`, actual_lines: actualLines });
    }
    if (step.context_start_line && step.context_end_line && step.context_end_line < step.context_start_line) {
      issues.push({ step: index + 1, type, location, reason: "代码上下文结束行小于起始行" });
    }
  }
  return { complete: issues.length === 0, issues };
}

function requiresReportEvidenceChain(f, verification) {
  return ["Critical", "High", "Medium"].includes(effectiveSeverity(f, verification));
}

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

const auditStartAgentRun = tool({
  description: "Create or resume the durable execution record for one D1-D10 agent. Call before applicability checks or scanning.",
  args: {
    session_id:     tool.schema.number().describe("Audit session ID"),
    dimension:      tool.schema.string().describe("Exactly one dimension: D1 ... D10"),
    agent_source:   tool.schema.string().describe("Dedicated agent name"),
    round_number:   tool.schema.number().optional().describe("Audit round, default 1"),
    runtime_handle: tool.schema.string().optional().describe("Native runtime/task handle when resumable by the host"),
    status:         tool.schema.string().optional().describe("QUEUED | RUNNING; default RUNNING"),
  },
  async execute(args) {
    const db = getDb();
    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) { db.close(); return JSON.stringify({ error: `Session ${args.session_id} not found` }); }
    const dimension = String(args.dimension ?? "").trim().toUpperCase();
    if (!/^D(?:10|[1-9])$/.test(dimension)) {
      db.close();
      return JSON.stringify({ error: "dimension must be exactly one of D1 ... D10" });
    }
    const round = args.round_number ?? 1;
    const status = String(args.status ?? "RUNNING").trim().toUpperCase();
    if (!["QUEUED", "RUNNING"].includes(status)) {
      db.close();
      return JSON.stringify({ error: "audit_start_agent_run status must be QUEUED or RUNNING" });
    }
    db.run(
      `INSERT INTO audit_agent_runs
         (session_id, dimension, agent_source, round_number, runtime_handle, status, started_at, heartbeat_at)
       VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT(session_id, dimension, round_number) DO UPDATE SET
         agent_source=excluded.agent_source,
         runtime_handle=COALESCE(excluded.runtime_handle, audit_agent_runs.runtime_handle),
         status=CASE
           WHEN audit_agent_runs.status IN ('INTERRUPTED','CHECKPOINTED') THEN 'RESUMING'
           WHEN audit_agent_runs.status IN ('COMPLETED','NOT_APPLICABLE') THEN audit_agent_runs.status
           ELSE excluded.status
         END,
         resumed_at=CASE
           WHEN audit_agent_runs.status IN ('INTERRUPTED','CHECKPOINTED') THEN CURRENT_TIMESTAMP
           ELSE audit_agent_runs.resumed_at
         END,
         heartbeat_at=CURRENT_TIMESTAMP,
         updated_at=CURRENT_TIMESTAMP`,
      [args.session_id, dimension, args.agent_source, round, args.runtime_handle ?? null, status]
    );
    const run = db.query(
      `SELECT * FROM audit_agent_runs WHERE session_id=? AND dimension=? AND round_number=?`
    ).get(args.session_id, dimension, round);
    const checkpoint = db.query(
      `SELECT * FROM audit_agent_checkpoints WHERE agent_run_id=? ORDER BY checkpoint_seq DESC LIMIT 1`
    ).get(run.id);
    db.close();
    return JSON.stringify({ agent_run_id: run.id, status: run.status, resumable: Boolean(checkpoint), latest_checkpoint: checkpoint ?? null });
  },
});

const auditCheckpointAgentRun = tool({
  description: "Persist a continuation checkpoint for an agent. Call after applicability, candidate enumeration, every completed candidate/module, and before budget exhaustion.",
  args: {
    agent_run_id:       tool.schema.number().describe("Agent run ID from audit_start_agent_run"),
    current_phase:      tool.schema.string().describe("Current phase or operation"),
    search_cursor:      tool.schema.string().optional().describe("Stable file/symbol/queue cursor"),
    remaining_work:     tool.schema.string().optional().describe("JSON array/object describing work not yet completed"),
    files_read:         tool.schema.string().optional().describe("JSON array of files already read"),
    grep_done:          tool.schema.string().optional().describe("JSON array of searches already executed"),
    open_candidate_ids: tool.schema.string().optional().describe("JSON array of OPEN/TIMEOUT candidate IDs"),
    active_trace:       tool.schema.string().optional().describe("JSON object for the current Source/Sink, control, config, or memory trace"),
    tool_usage:         tool.schema.string().optional().describe("JSON object with tool/token budget usage"),
    checkpoint_reason:  tool.schema.string().optional().describe("applicability_checked | candidates_saved | candidate_closed | module_done | budget_guard | pre_complete"),
  },
  async execute(args) {
    const jsonFields = ["remaining_work", "files_read", "grep_done", "open_candidate_ids", "active_trace", "tool_usage"];
    const normalized = {};
    for (const field of jsonFields) {
      const fallback = field === "active_trace" || field === "tool_usage" ? "{}" : "[]";
      const result = requireJsonText(args[field], field, fallback);
      if (result.error) return JSON.stringify({ error: result.error });
      normalized[field] = result.value;
    }
    const db = getDb();
    const run = db.query("SELECT id, status FROM audit_agent_runs WHERE id=?").get(args.agent_run_id);
    if (!run) { db.close(); return JSON.stringify({ error: `Agent run ${args.agent_run_id} not found` }); }
    if (["COMPLETED", "NOT_APPLICABLE", "FAILED", "SKIPPED"].includes(run.status)) {
      db.close();
      return JSON.stringify({ error: `Cannot checkpoint terminal agent run ${args.agent_run_id} (${run.status})` });
    }
    const next = db.query(
      "SELECT COALESCE(MAX(checkpoint_seq), 0) + 1 AS seq FROM audit_agent_checkpoints WHERE agent_run_id=?"
    ).get(args.agent_run_id)?.seq ?? 1;
    const result = db.run(
      `INSERT INTO audit_agent_checkpoints
         (agent_run_id, checkpoint_seq, current_phase, search_cursor, remaining_work,
          files_read, grep_done, open_candidate_ids, active_trace, tool_usage, checkpoint_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [args.agent_run_id, next, args.current_phase, args.search_cursor ?? null,
       normalized.remaining_work, normalized.files_read, normalized.grep_done,
       normalized.open_candidate_ids, normalized.active_trace, normalized.tool_usage,
       args.checkpoint_reason ?? null]
    );
    db.run(
      `UPDATE audit_agent_runs SET current_phase=?, status='RUNNING', heartbeat_at=CURRENT_TIMESTAMP,
       updated_at=CURRENT_TIMESTAMP WHERE id=?`,
      [args.current_phase, args.agent_run_id]
    );
    db.close();
    return JSON.stringify({ checkpoint_id: result.lastInsertRowid, checkpoint_seq: next, agent_run_id: args.agent_run_id });
  },
});

const auditGetAgentResumeContext = tool({
  description: "Load the latest durable checkpoint and unfinished candidates. Use instead of restarting an interrupted agent scan.",
  args: {
    agent_run_id: tool.schema.number().optional().describe("Known agent run ID"),
    session_id:   tool.schema.number().optional().describe("Session ID when agent_run_id is unknown"),
    dimension:    tool.schema.string().optional().describe("D1 ... D10 when agent_run_id is unknown"),
    round_number: tool.schema.number().optional().describe("Round when agent_run_id is unknown"),
  },
  async execute(args) {
    const db = getDb();
    let run;
    if (args.agent_run_id) {
      run = db.query("SELECT * FROM audit_agent_runs WHERE id=?").get(args.agent_run_id);
    } else if (args.session_id && args.dimension) {
      run = db.query(
        `SELECT * FROM audit_agent_runs WHERE session_id=? AND dimension=? AND round_number=?`
      ).get(args.session_id, args.dimension, args.round_number ?? 1);
    } else {
      db.close();
      return JSON.stringify({ error: "Provide agent_run_id or session_id + dimension" });
    }
    if (!run) { db.close(); return JSON.stringify({ error: "Agent run not found" }); }
    const checkpoint = db.query(
      `SELECT * FROM audit_agent_checkpoints WHERE agent_run_id=? ORDER BY checkpoint_seq DESC LIMIT 1`
    ).get(run.id);
    const candidates = db.query(
      `SELECT * FROM audit_candidates
       WHERE session_id=? AND dimension=? AND status IN ('OPEN','TIMEOUT')
       ORDER BY file_path, line_number, id`
    ).all(run.session_id, run.dimension);
    db.close();
    return JSON.stringify({ run, checkpoint: checkpoint ?? null, unfinished_candidates: candidates });
  },
});

const auditResumeAgentRun = tool({
  description: "Mark an interrupted agent as resuming after its native runtime handle or durable checkpoint has been selected.",
  args: {
    agent_run_id:   tool.schema.number().describe("Agent run ID"),
    runtime_handle: tool.schema.string().optional().describe("Updated native runtime/task handle"),
  },
  async execute(args) {
    const db = getDb();
    const current = db.query("SELECT id, status FROM audit_agent_runs WHERE id=?").get(args.agent_run_id);
    if (!current) { db.close(); return JSON.stringify({ error: "Agent run not found" }); }
    if (!["INTERRUPTED", "CHECKPOINTED"].includes(current.status)) {
      db.close();
      return JSON.stringify({ error: `Agent run ${args.agent_run_id} is ${current.status}; only interrupted/checkpointed runs may resume` });
    }
    const result = db.run(
      `UPDATE audit_agent_runs SET status='RESUMING', runtime_handle=COALESCE(?, runtime_handle),
       resumed_at=CURRENT_TIMESTAMP, heartbeat_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
       WHERE id=?`,
      [args.runtime_handle ?? null, args.agent_run_id]
    );
    const run = db.query("SELECT * FROM audit_agent_runs WHERE id=?").get(args.agent_run_id);
    db.close();
    return JSON.stringify(result.changes ? { agent_run_id: args.agent_run_id, status: run.status } : { error: "Agent run not found" });
  },
});

const auditFinishAgentRun = tool({
  description: "Finalize or interrupt an agent run with a structured reason. Every D1-D10 agent must call this exactly once per invocation.",
  args: {
    agent_run_id: tool.schema.number().describe("Agent run ID"),
    status:       tool.schema.string().describe("COMPLETED | NOT_APPLICABLE | INTERRUPTED | FAILED | SKIPPED"),
    reason:       tool.schema.string().optional().describe("Required for all non-COMPLETED statuses"),
    skip_code:    tool.schema.string().optional().describe("Stable reason code for NOT_APPLICABLE/SKIPPED"),
  },
  async execute(args) {
    const status = String(args.status ?? "").trim().toUpperCase();
    if (!["COMPLETED", "NOT_APPLICABLE", "INTERRUPTED", "FAILED", "SKIPPED"].includes(status)) {
      return JSON.stringify({ error: `Invalid terminal/interruption status: ${status}` });
    }
    if (status !== "COMPLETED" && !String(args.reason ?? "").trim()) {
      return JSON.stringify({ error: `reason is required for ${status}` });
    }
    const db = getDb();
    db.run(
      `UPDATE audit_agent_runs SET status=?, skip_code=?, status_reason=?,
       interrupted_at=CASE WHEN ?='INTERRUPTED' THEN CURRENT_TIMESTAMP ELSE interrupted_at END,
       completed_at=CASE WHEN ? IN ('COMPLETED','NOT_APPLICABLE','FAILED','SKIPPED') THEN CURRENT_TIMESTAMP ELSE completed_at END,
       heartbeat_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
      [status, args.skip_code ?? null, args.reason ?? null, status, status, args.agent_run_id]
    );
    const run = db.query("SELECT * FROM audit_agent_runs WHERE id=?").get(args.agent_run_id);
    db.close();
    return JSON.stringify(run ? { agent_run_id: run.id, status: run.status, reason: run.status_reason } : { error: "Agent run not found" });
  },
});

const auditListAgentRuns = tool({
  description: "List D1-D10 execution records for evaluation/reporting, including queued, not-applicable, interrupted, and completed agents.",
  args: {
    session_id: tool.schema.number().describe("Audit session ID"),
  },
  async execute(args) {
    const db = getDb();
    const rows = db.query(
      `SELECT * FROM audit_agent_runs WHERE session_id=?
       ORDER BY CAST(SUBSTR(dimension, 2) AS INTEGER), round_number`
    ).all(args.session_id);
    db.close();
    return JSON.stringify({ session_id: args.session_id, agent_runs: rows });
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
  description: "Save sink chain nodes for a finding. Call after audit_save_finding with the finding_id. Pass a non-empty JSON array; empty or evidence-less steps are rejected.",
  args: {
    finding_id: tool.schema.number().describe("Finding ID from audit_save_finding"),
    steps: tool.schema.string().describe(
      'Non-empty JSON array. Preferred step: {"step_type":"Source|Transform|Sanitizer|Sink","file_path":"...","line_number":42,"function_name":"Class.method","context_start_line":36,"context_end_line":49,"code_snippet":"multi-line context","notes":"..."}'
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
    const normalized = normalizeSinkChainSteps(steps);
    if (normalized.error) {
      db.close();
      return JSON.stringify({ error: normalized.error });
    }
    const insert = db.prepare(
      `INSERT INTO sink_chains
         (finding_id, step_order, step_type, file_path, line_number, function_name,
          context_start_line, context_end_line, code_snippet, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (let i = 0; i < normalized.steps.length; i++) {
      const s = normalized.steps[i];
      insert.run([args.finding_id, i, s.step_type ?? null, s.file_path ?? null,
                  s.line_number ?? null, s.function_name ?? null,
                  s.context_start_line ?? null, s.context_end_line ?? null,
                  s.code_snippet ?? null, s.notes ?? null]);
    }
    db.close();
    return JSON.stringify({ saved: normalized.steps.length, discarded_steps: normalized.discarded });
  },
});

const auditSaveSinkCandidates = tool({
  description: "Legacy compatibility for old sink ledgers. New D1-D10 agents must use audit_upsert_candidates with an agent_run_id.",
  args: {
    session_id:    tool.schema.number().describe("Session ID from audit_init_session"),
    dimension:     tool.schema.string().optional().describe("Default dimension for entries, e.g. D1, D4, D5, D6"),
    agent_source:  tool.schema.string().optional().describe("Agent name, e.g. audit-d1-injection"),
    round_number:  tool.schema.number().optional().describe("Audit round number"),
    ledger_file:   tool.schema.string().optional().describe("Deprecated compatibility field; do not create or pass intermediate JSONL ledger files in new workflows."),
    candidates:    tool.schema.string().describe(
      'JSON array. Each item: {"dimension":"D1","sink_type":"SQL_DYNAMIC","pattern":"...","file_path":"...","line_number":42,"code_snippet":"...","status":"TRACED_SAFE|OPEN|...","reason":"...","evidence":"...","risk":"High","path_status":"COMPLETE|PARTIAL|NOT_REQUIRED|UNKNOWN","traced_depth":3,"finding_id":1}'
    ),
  },
  async execute(args) {
    const db = getDb();
    let candidates;
    try {
      candidates = JSON.parse(args.candidates);
    } catch {
      db.close();
      return JSON.stringify({ error: "candidates must be a valid JSON array" });
    }
    if (!Array.isArray(candidates)) {
      db.close();
      return JSON.stringify({ error: "candidates must be a JSON array" });
    }

    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) {
      db.close();
      return JSON.stringify({ error: `Session ${args.session_id} not found` });
    }

    const insert = db.prepare(
      `INSERT INTO sink_candidates
         (session_id, finding_id, dimension, agent_source, round_number,
          sink_type, pattern, file_path, line_number, code_snippet,
          status, reason, evidence, risk, path_status, traced_depth, ledger_file)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const byStatus = {};
    const ids = [];
    for (const raw of candidates) {
      const status = normalizeSinkCandidateStatus(raw?.status);
      byStatus[status] = (byStatus[status] ?? 0) + 1;
      const result = insert.run([
        args.session_id,
        raw?.finding_id ?? null,
        raw?.dimension ?? args.dimension ?? null,
        raw?.agent_source ?? args.agent_source ?? null,
        raw?.round_number ?? args.round_number ?? 1,
        raw?.sink_type ?? null,
        raw?.pattern ?? null,
        raw?.file_path ?? null,
        raw?.line_number ?? null,
        raw?.code_snippet ?? null,
        status,
        raw?.reason ?? null,
        raw?.evidence ?? null,
        raw?.risk ?? null,
        normalizePathStatus(raw?.path_status),
        raw?.traced_depth ?? null,
        raw?.ledger_file ?? args.ledger_file ?? null,
      ]);
      ids.push(result.lastInsertRowid);
    }

    const unchecked = (byStatus.OPEN ?? 0) + (byStatus.TIMEOUT ?? 0);
    db.close();
    return JSON.stringify({
      saved: candidates.length,
      unchecked,
      by_status: byStatus,
      candidate_ids: ids.slice(0, 100),
      candidate_ids_truncated: ids.length > 100,
    });
  },
});

const auditGetUncheckedSinks = tool({
  description: "Fetch OPEN/TIMEOUT sink candidates for an audit session. Use during R2 planning to clear sink-driven coverage gaps.",
  args: {
    session_id:   tool.schema.number().describe("Session ID from audit_init_session"),
    dimension:    tool.schema.string().optional().describe("Optional dimension filter, e.g. D1"),
    agent_source: tool.schema.string().optional().describe("Optional agent source filter"),
    limit:        tool.schema.number().optional().describe("Maximum entries to return, default 100"),
  },
  async execute(args) {
    const db = getDb();
    const where = ["session_id=?", "status IN ('OPEN','TIMEOUT')"];
    const params = [args.session_id];
    if (args.dimension) {
      where.push("dimension=?");
      params.push(args.dimension);
    }
    if (args.agent_source) {
      where.push("agent_source=?");
      params.push(args.agent_source);
    }
    const limit = Math.max(1, Math.min(args.limit ?? 100, 500));
    const rows = db.query(
      `SELECT * FROM sink_candidates
       WHERE ${where.join(" AND ")}
       ORDER BY dimension, file_path, line_number
       LIMIT ?`
    ).all(...params, limit);
    const total = db.query(
      `SELECT COUNT(*) AS count FROM sink_candidates WHERE ${where.join(" AND ")}`
    ).get(...params)?.count ?? 0;
    db.close();
    return JSON.stringify({
      session_id: args.session_id,
      count: total,
      returned: rows.length,
      truncated: total > rows.length,
      unchecked_sinks: rows,
    });
  },
});

const auditGetSinkCoverage = tool({
  description: "Summarize sink-driven candidate coverage for a session, grouped by dimension.",
  args: {
    session_id: tool.schema.number().describe("Session ID from audit_init_session"),
  },
  async execute(args) {
    const db = getDb();
    const rows = db.query(
      `SELECT
         dimension,
         COUNT(*) AS candidates,
         SUM(CASE WHEN status NOT IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS triaged,
         SUM(CASE WHEN status IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS unchecked,
         SUM(CASE WHEN status IN ('EXCLUDED_TEST','EXCLUDED_VENDOR') THEN 1 ELSE 0 END) AS excluded,
         SUM(CASE WHEN status='TRACED_VULN' THEN 1 ELSE 0 END) AS findings,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H') THEN 1 ELSE 0 END) AS high_risk,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H')
                   AND path_status='COMPLETE' THEN 1 ELSE 0 END) AS high_path_complete
       FROM sink_candidates
       WHERE session_id=?
       GROUP BY dimension
       ORDER BY dimension`
    ).all(args.session_id);

    const summary = rows.map((row) => ({
      ...row,
      sink_triage:
        row.candidates > 0 ? `${row.triaged}/${row.candidates}` : "0/0",
      sink_triage_percent:
        row.candidates > 0 ? Number(((row.triaged / row.candidates) * 100).toFixed(2)) : 100,
      high_path:
        row.high_risk > 0 ? `${row.high_path_complete}/${row.high_risk}` : "0/0",
      high_path_percent:
        row.high_risk > 0 ? Number(((row.high_path_complete / row.high_risk) * 100).toFixed(2)) : 100,
      covered:
        row.candidates > 0 &&
        row.unchecked === 0 &&
        (row.high_risk === 0 || row.high_path_complete === row.high_risk),
    }));
    db.close();
    return JSON.stringify({ session_id: args.session_id, dimensions: summary });
  },
});

const auditSaveCandidates = tool({
  description: "Idempotently upsert generic audit candidates for sink, control, config, and memory-driven audits. Every D1-D10 agent calls this incrementally before promoting confirmed candidates to findings.",
  args: {
    session_id:     tool.schema.number().describe("Session ID from audit_init_session"),
    agent_run_id:   tool.schema.number().describe("Durable agent run ID from audit_start_agent_run; candidates cannot be saved outside an agent run"),
    candidate_kind: tool.schema.string().optional().describe("Default kind: SINK | CONTROL | CONFIG | MEMORY"),
    dimension:      tool.schema.string().optional().describe("Default dimension for entries, e.g. D1, D3, D8"),
    agent_source:   tool.schema.string().optional().describe("Dedicated agent name, e.g. audit-d3-authorization"),
    round_number:   tool.schema.number().optional().describe("Audit round number"),
    candidates:     tool.schema.string().describe(
      'JSON array. Each item may include candidate_key; otherwise a stable key is derived from kind/rule/file/line/symbol. Example: {"candidate_kind":"CONTROL","dimension":"D3","rule_id":"MISSING_AUTHZ_CONTROL","candidate_type":"CONTROL_MISSING","evidence_type":"ANNOTATION_ABSENT","file_path":"...","line_number":42,"code_snippet":"...","status":"TRACED_VULN|TRACED_SAFE|OPEN|...","reason":"...","evidence":"...","risk":"High","path_status":"COMPLETE|PARTIAL|NOT_REQUIRED|UNKNOWN","traced_depth":3,"finding_id":1}'
    ),
  },
  async execute(args) {
    const db = getDb();
    let candidates;
    try {
      candidates = JSON.parse(args.candidates);
    } catch {
      db.close();
      return JSON.stringify({ error: "candidates must be a valid JSON array" });
    }
    if (!Array.isArray(candidates)) {
      db.close();
      return JSON.stringify({ error: "candidates must be a JSON array" });
    }

    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) {
      db.close();
      return JSON.stringify({ error: `Session ${args.session_id} not found` });
    }
    const agentRun = db.query(
      "SELECT id, session_id, dimension, agent_source, round_number, status FROM audit_agent_runs WHERE id=?"
    ).get(args.agent_run_id);
    if (!agentRun) {
      db.close();
      return JSON.stringify({ error: `Agent run ${args.agent_run_id} not found` });
    }
    if (agentRun.session_id !== args.session_id) {
      db.close();
      return JSON.stringify({ error: `Agent run ${args.agent_run_id} does not belong to session ${args.session_id}` });
    }
    if (!["RUNNING", "RESUMING"].includes(agentRun.status)) {
      db.close();
      return JSON.stringify({ error: `Agent run ${args.agent_run_id} is ${agentRun.status}; candidates require a running agent` });
    }
    if (args.round_number !== undefined && args.round_number !== agentRun.round_number) {
      db.close();
      return JSON.stringify({ error: `Candidate round ${args.round_number} does not match agent run round ${agentRun.round_number}` });
    }

    const upsert = db.prepare(
      `INSERT INTO audit_candidates
         (session_id, finding_id, dimension, agent_source, round_number, agent_run_id, candidate_key,
          candidate_kind, rule_id, candidate_type, evidence_type,
          file_path, line_number, code_snippet, status, reason, evidence,
          risk, path_status, traced_depth)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_id, dimension, candidate_key) DO UPDATE SET
         finding_id=COALESCE(excluded.finding_id, audit_candidates.finding_id),
         agent_source=excluded.agent_source,
         round_number=excluded.round_number,
         agent_run_id=COALESCE(excluded.agent_run_id, audit_candidates.agent_run_id),
         candidate_kind=excluded.candidate_kind,
         rule_id=excluded.rule_id,
         candidate_type=excluded.candidate_type,
         evidence_type=excluded.evidence_type,
         file_path=excluded.file_path,
         line_number=excluded.line_number,
         code_snippet=COALESCE(excluded.code_snippet, audit_candidates.code_snippet),
         status=excluded.status,
         reason=excluded.reason,
         evidence=excluded.evidence,
         risk=excluded.risk,
         path_status=excluded.path_status,
         traced_depth=excluded.traced_depth,
         updated_at=CURRENT_TIMESTAMP`
    );

    const byStatus = {};
    const byKind = {};
    const ids = [];
    let inserted = 0;
    let updated = 0;
    for (const raw of candidates) {
      const status = normalizeSinkCandidateStatus(raw?.status);
      const kind = String(raw?.candidate_kind ?? args.candidate_kind ?? "UNKNOWN").trim().toUpperCase();
      if (!["SINK", "CONTROL", "CONFIG", "MEMORY"].includes(kind)) {
        db.close();
        return JSON.stringify({ error: `candidate_kind must be SINK, CONTROL, CONFIG, or MEMORY; got '${kind}'` });
      }
      const dimension = String(raw?.dimension ?? args.dimension ?? agentRun.dimension).trim().toUpperCase();
      if (!dimension || !/^D(?:10|[1-9])$/.test(String(dimension))) {
        db.close();
        return JSON.stringify({ error: `Each candidate must use exactly one dimension D1-D10; got '${dimension}'` });
      }
      if (dimension !== agentRun.dimension) {
        db.close();
        return JSON.stringify({ error: `Candidate dimension ${dimension} does not match agent run dimension ${agentRun.dimension}` });
      }
      const requestedAgent = raw?.agent_source ?? args.agent_source;
      if (requestedAgent && requestedAgent !== agentRun.agent_source) {
        db.close();
        return JSON.stringify({ error: `Candidate agent_source '${requestedAgent}' does not match agent run '${agentRun.agent_source}'` });
      }
      const key = stableCandidateKey(raw, { candidate_kind: kind });
      const existing = db.query(
        `SELECT id FROM audit_candidates WHERE session_id=? AND dimension=? AND candidate_key=?`
      ).get(args.session_id, dimension, key);
      byStatus[status] = (byStatus[status] ?? 0) + 1;
      byKind[kind] = (byKind[kind] ?? 0) + 1;
      upsert.run([
        args.session_id,
        raw?.finding_id ?? null,
        dimension,
        agentRun.agent_source,
        agentRun.round_number,
        agentRun.id,
        key,
        kind,
        raw?.rule_id ?? null,
        raw?.candidate_type ?? null,
        raw?.evidence_type ?? null,
        raw?.file_path ?? null,
        raw?.line_number ?? null,
        raw?.code_snippet ?? null,
        status,
        raw?.reason ?? null,
        raw?.evidence ?? null,
        raw?.risk ?? null,
        normalizePathStatus(raw?.path_status),
        raw?.traced_depth ?? null,
      ]);
      const row = db.query(
        `SELECT id FROM audit_candidates WHERE session_id=? AND dimension=? AND candidate_key=?`
      ).get(args.session_id, dimension, key);
      ids.push(row.id);
      if (existing) updated += 1; else inserted += 1;
    }

    const unchecked = (byStatus.OPEN ?? 0) + (byStatus.TIMEOUT ?? 0);
    db.close();
    return JSON.stringify({
      saved: candidates.length,
      inserted,
      updated,
      unchecked,
      by_status: byStatus,
      by_kind: byKind,
      candidate_ids: ids.slice(0, 100),
      candidate_ids_truncated: ids.length > 100,
    });
  },
});

const auditGetUncheckedCandidates = tool({
  description: "Fetch OPEN/TIMEOUT generic audit candidates for an audit session. Use during R2 planning to clear candidate coverage gaps.",
  args: {
    session_id:      tool.schema.number().describe("Session ID from audit_init_session"),
    candidate_kind:  tool.schema.string().optional().describe("Optional kind filter: SINK | CONTROL | CONFIG | MEMORY"),
    dimension:       tool.schema.string().optional().describe("Optional dimension filter, e.g. D3"),
    agent_source:    tool.schema.string().optional().describe("Optional agent source filter"),
    limit:           tool.schema.number().optional().describe("Maximum entries to return, default 100"),
  },
  async execute(args) {
    const db = getDb();
    const where = ["session_id=?", "status IN ('OPEN','TIMEOUT')"];
    const params = [args.session_id];
    if (args.candidate_kind) {
      where.push("candidate_kind=?");
      params.push(String(args.candidate_kind).trim().toUpperCase());
    }
    if (args.dimension) {
      where.push("dimension=?");
      params.push(args.dimension);
    }
    if (args.agent_source) {
      where.push("agent_source=?");
      params.push(args.agent_source);
    }
    const limit = Math.max(1, Math.min(args.limit ?? 100, 500));
    const rows = db.query(
      `SELECT * FROM audit_candidates
       WHERE ${where.join(" AND ")}
       ORDER BY candidate_kind, dimension, file_path, line_number
       LIMIT ?`
    ).all(...params, limit);
    const total = db.query(
      `SELECT COUNT(*) AS count FROM audit_candidates WHERE ${where.join(" AND ")}`
    ).get(...params)?.count ?? 0;
    db.close();
    return JSON.stringify({
      session_id: args.session_id,
      count: total,
      returned: rows.length,
      truncated: total > rows.length,
      unchecked_candidates: rows,
    });
  },
});

const auditGetCandidateCoverage = tool({
  description: "Summarize generic audit candidate coverage for a session, grouped by kind and dimension.",
  args: {
    session_id:     tool.schema.number().describe("Session ID from audit_init_session"),
    candidate_kind: tool.schema.string().optional().describe("Optional kind filter: SINK | CONTROL | CONFIG | MEMORY"),
  },
  async execute(args) {
    const db = getDb();
    const where = ["session_id=?"];
    const params = [args.session_id];
    if (args.candidate_kind) {
      where.push("candidate_kind=?");
      params.push(String(args.candidate_kind).trim().toUpperCase());
    }
    const rows = db.query(
      `SELECT
         candidate_kind,
         dimension,
         COUNT(*) AS candidates,
         SUM(CASE WHEN status NOT IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS triaged,
         SUM(CASE WHEN status IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS unchecked,
         SUM(CASE WHEN status IN ('EXCLUDED_TEST','EXCLUDED_VENDOR') THEN 1 ELSE 0 END) AS excluded,
         SUM(CASE WHEN status='TRACED_VULN' THEN 1 ELSE 0 END) AS findings,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H') THEN 1 ELSE 0 END) AS high_risk,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H')
                   AND path_status IN ('COMPLETE','NOT_REQUIRED') THEN 1 ELSE 0 END) AS high_path_complete
       FROM audit_candidates
       WHERE ${where.join(" AND ")}
       GROUP BY candidate_kind, dimension
       ORDER BY candidate_kind, dimension`
    ).all(...params);

    const summary = rows.map((row) => ({
      ...row,
      candidate_triage:
        row.candidates > 0 ? `${row.triaged}/${row.candidates}` : "0/0",
      candidate_triage_percent:
        row.candidates > 0 ? Number(((row.triaged / row.candidates) * 100).toFixed(2)) : 100,
      high_path:
        row.high_risk > 0 ? `${row.high_path_complete}/${row.high_risk}` : "0/0",
      high_path_percent:
        row.high_risk > 0 ? Number(((row.high_path_complete / row.high_risk) * 100).toFixed(2)) : 100,
      covered:
        row.candidates > 0 &&
        row.unchecked === 0 &&
        (row.high_risk === 0 || row.high_path_complete === row.high_risk),
    }));
    db.close();
    return JSON.stringify({ session_id: args.session_id, dimensions: summary });
  },
});

const auditSaveVerification = tool({
  description: "Save the independent per-finding verification result. Narrative evidence and conclusion must be Chinese.",
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
    conclusion:       tool.schema.string().describe("Chinese final verification conclusion"),
  },
  async execute(args) {
    const enums = {
      verdict: ["VERIFIED", "PARTIAL", "SINK_ONLY", "FALSE_POSITIVE"],
      source_status: ["TRUE_SOURCE", "CONDITIONAL_SOURCE", "PSEUDO_SOURCE", "NO_SOURCE"],
      sink_status: ["CONFIRMED", "UNCLEAR", "NOT_FOUND"],
      sanitizer_status: ["NONE", "BYPASSABLE", "EFFECTIVE", "UNKNOWN"],
      exploitability: ["PRACTICAL", "CONDITIONAL", "THEORETICAL", "NOT_EXPLOITABLE"],
      severity_action: ["KEEP", "DOWNGRADE_1", "DOWNGRADE_2", "DROP"],
    };
    for (const [field, allowed] of Object.entries(enums)) {
      if (!allowed.includes(args[field])) return JSON.stringify({ error: `${field} must be one of ${allowed.join(" | ")}` });
    }
    for (const field of ["true_source", "key_gap", "exploit_method"]) {
      const languageError = chineseTextError(field, args[field], false);
      if (languageError) return JSON.stringify({ error: languageError });
    }
    const conclusionError = chineseTextError("conclusion", args.conclusion);
    if (conclusionError) return JSON.stringify({ error: conclusionError });
    if (["TRUE_SOURCE", "CONDITIONAL_SOURCE"].includes(args.source_status) && !args.true_source) {
      return JSON.stringify({ error: "true_source is required for a confirmed or conditional source" });
    }
    if (["PRACTICAL", "CONDITIONAL"].includes(args.exploitability) && !args.exploit_method) {
      return JSON.stringify({ error: "exploit_method is required for practical or conditional exploitation" });
    }
    const db = getDb();
    const finding = db.query("SELECT id FROM findings WHERE id=?").get(args.finding_id);
    if (!finding) { db.close(); return JSON.stringify({ error: `Finding ${args.finding_id} not found` }); }
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
  description: "Update the canonical finding after verification. Use this to write back enriched root cause, exploit method, PoC, severity/confidence changes, and optionally replace the sink chain before final report generation. Empty or evidence-less sink_chain_steps are rejected.",
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
      'Optional non-empty JSON array. Preferred step: {"step_type":"Source|Transform|Sanitizer|Sink","file_path":"...","line_number":42,"function_name":"Class.method","context_start_line":36,"context_end_line":49,"code_snippet":"multi-line context","notes":"..."}'
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
    let discardedReplacementSteps = 0;
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
      const normalized = normalizeSinkChainSteps(replacementSteps);
      if (normalized.error) {
        db.close();
        return JSON.stringify({ error: normalized.error });
      }
      replacementSteps = normalized.steps;
      discardedReplacementSteps = normalized.discarded;
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
      db.run(`UPDATE findings SET ${updates.join(", ")}, updated_at=CURRENT_TIMESTAMP WHERE id=?`, [...values, args.finding_id]);
    }

    let replaced_steps = 0;
    if (replacementSteps !== undefined) {
      db.run("DELETE FROM sink_chains WHERE finding_id=?", [args.finding_id]);
      const insert = db.prepare(
        `INSERT INTO sink_chains
           (finding_id, step_order, step_type, file_path, line_number, function_name,
            context_start_line, context_end_line, code_snippet, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (let i = 0; i < replacementSteps.length; i++) {
        const s = replacementSteps[i];
        insert.run([args.finding_id, i, s.step_type ?? null, s.file_path ?? null,
                    s.line_number ?? null, s.function_name ?? null,
                    s.context_start_line ?? null, s.context_end_line ?? null,
                    s.code_snippet ?? null, s.notes ?? null]);
      }
      replaced_steps = replacementSteps.length;
    }

    db.close();
    return JSON.stringify({
      ok: true,
      updated_fields: updates.length,
      replaced_steps,
      discarded_steps: discardedReplacementSteps,
    });
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
      const sinkChainSteps = db.query(
        "SELECT * FROM sink_chains WHERE finding_id=? ORDER BY step_order"
      ).all(f.id);
      const chainStatus = chainEvidenceStatus(sinkChainSteps);
      const needsChainRepair = requiresReportEvidenceChain(f, latestVerification) && !chainStatus.complete;
      if (latestVerification && !args.include_verified && !needsChainRepair) continue;

      findings.push({
        ...f,
        sink_chain_steps: sinkChainSteps,
        reportable_sink_chain_steps: chainStatus.steps,
        chain_quality: {
          has_evidence: chainStatus.hasEvidence,
          has_source: chainStatus.hasSource,
          has_sink: chainStatus.hasSink,
          complete: chainStatus.complete,
          needs_repair: needsChainRepair,
        },
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

const auditListFindingsForDetail = tool({
  description: "List every database finding and its dedicated detail-report run. The report coordinator uses one agent invocation per returned finding.",
  args: {
    session_id: tool.schema.number().describe("Audit session ID"),
    include_terminal: tool.schema.boolean().optional().describe("Include COMPLETED and REJECTED runs; defaults to false"),
  },
  async execute(args) {
    const db = getDb();
    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) { db.close(); return JSON.stringify({ error: `Session ${args.session_id} not found` }); }
    const rows = db.query(
      `SELECT f.*,
              r.id AS detail_run_id, r.status AS detail_run_status, r.current_phase,
              r.runtime_handle, r.status_reason, r.heartbeat_at,
              d.component_name, d.report_title, d.content_version,
              a.markdown_path, a.language_status, a.content_hash,
              v.verdict, v.severity_action, v.conclusion AS verification_conclusion
       FROM findings f
       LEFT JOIN finding_detail_runs r ON r.finding_id=f.id
       LEFT JOIN finding_report_details d ON d.finding_id=f.id
       LEFT JOIN finding_report_artifacts a
         ON a.finding_id=f.id AND a.content_version=d.content_version
       LEFT JOIN finding_verifications v ON v.id=(
         SELECT id FROM finding_verifications WHERE finding_id=f.id ORDER BY id DESC LIMIT 1
       )
       WHERE f.session_id=?
       ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, f.id`
    ).all(args.session_id);
    const filtered = args.include_terminal
      ? rows
      : rows.filter((row) => !["COMPLETED", "REJECTED"].includes(row.detail_run_status));
    db.close();
    return JSON.stringify({
      session_id: args.session_id,
      count: filtered.length,
      findings: filtered,
      dispatch_contract: "每个 finding_id 必须单独启动一次 audit-verification Agent",
    });
  },
});

const auditStartFindingDetailRun = tool({
  description: "Create or resume the durable per-finding verification/report run. Call once at the beginning of each dedicated finding agent invocation.",
  args: {
    session_id: tool.schema.number().describe("Audit session ID"),
    finding_id: tool.schema.number().describe("Exactly one finding ID"),
    agent_source: tool.schema.string().optional().describe("Defaults to audit-verification"),
    runtime_handle: tool.schema.string().optional().describe("Native task handle when the host can resume it"),
  },
  async execute(args) {
    const db = getDb();
    const finding = db.query("SELECT id, session_id FROM findings WHERE id=?").get(args.finding_id);
    if (!finding || finding.session_id !== args.session_id) {
      db.close();
      return JSON.stringify({ error: `Finding ${args.finding_id} does not belong to session ${args.session_id}` });
    }
    db.run(
      `INSERT INTO finding_detail_runs
         (session_id, finding_id, agent_source, runtime_handle, status, current_phase, started_at, heartbeat_at)
       VALUES (?, ?, ?, ?, 'RUNNING', '读取上下文', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT(finding_id) DO UPDATE SET
         agent_source=excluded.agent_source,
         runtime_handle=COALESCE(excluded.runtime_handle, finding_detail_runs.runtime_handle),
         status=CASE
           WHEN finding_detail_runs.status IN ('INTERRUPTED','CHECKPOINTED') THEN 'RESUMING'
           WHEN finding_detail_runs.status IN ('COMPLETED','REJECTED') THEN finding_detail_runs.status
           ELSE 'RUNNING'
         END,
         resumed_at=CASE
           WHEN finding_detail_runs.status IN ('INTERRUPTED','CHECKPOINTED') THEN CURRENT_TIMESTAMP
           ELSE finding_detail_runs.resumed_at
         END,
         heartbeat_at=CURRENT_TIMESTAMP,
         updated_at=CURRENT_TIMESTAMP`,
      [args.session_id, args.finding_id, args.agent_source ?? "audit-verification", args.runtime_handle ?? null]
    );
    const run = db.query("SELECT * FROM finding_detail_runs WHERE finding_id=?").get(args.finding_id);
    const checkpoint = db.query(
      "SELECT * FROM finding_detail_checkpoints WHERE detail_run_id=? ORDER BY checkpoint_seq DESC LIMIT 1"
    ).get(run.id);
    db.close();
    return JSON.stringify({
      detail_run_id: run.id,
      status: run.status,
      resumable: Boolean(checkpoint),
      latest_checkpoint: checkpoint ?? null,
      terminal: ["COMPLETED", "REJECTED"].includes(run.status),
    });
  },
});

const auditCheckpointFindingDetailRun = tool({
  description: "Save a continuation checkpoint for one finding agent. Use after evidence, exploit, remediation, and render phases and before interruption.",
  args: {
    detail_run_id: tool.schema.number().describe("Run ID from audit_start_finding_detail_run"),
    current_phase: tool.schema.string().describe("Chinese phase name"),
    search_cursor: tool.schema.string().optional().describe("Stable file/symbol/task cursor"),
    remaining_work: tool.schema.string().optional().describe("JSON array/object of remaining work"),
    files_read: tool.schema.string().optional().describe("JSON array of files already read"),
    active_trace: tool.schema.string().optional().describe("JSON object for the active evidence trace"),
    tool_usage: tool.schema.string().optional().describe("JSON object with budget/tool usage"),
    checkpoint_reason: tool.schema.string().optional().describe("evidence_done | exploit_done | remediation_done | budget_guard | pre_render"),
  },
  async execute(args) {
    const phaseError = chineseTextError("current_phase", args.current_phase);
    if (phaseError) return JSON.stringify({ error: phaseError });
    const normalized = {};
    for (const [field, fallback, type] of [
      ["remaining_work", [], "array"], ["files_read", [], "array"],
      ["active_trace", {}, "object"], ["tool_usage", {}, "object"],
    ]) {
      const result = parseJsonField(args[field], field, fallback, type);
      if (result.error) return JSON.stringify({ error: result.error });
      normalized[field] = result.value;
    }
    const db = getDb();
    const run = db.query("SELECT id, status FROM finding_detail_runs WHERE id=?").get(args.detail_run_id);
    if (!run) { db.close(); return JSON.stringify({ error: `Detail run ${args.detail_run_id} not found` }); }
    if (["COMPLETED", "REJECTED", "FAILED", "SKIPPED"].includes(run.status)) {
      db.close();
      return JSON.stringify({ error: `Cannot checkpoint terminal detail run ${args.detail_run_id} (${run.status})` });
    }
    const seq = db.query(
      "SELECT COALESCE(MAX(checkpoint_seq), 0) + 1 AS seq FROM finding_detail_checkpoints WHERE detail_run_id=?"
    ).get(args.detail_run_id)?.seq ?? 1;
    const result = db.run(
      `INSERT INTO finding_detail_checkpoints
         (detail_run_id, checkpoint_seq, current_phase, search_cursor, remaining_work,
          files_read, active_trace, tool_usage, checkpoint_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [args.detail_run_id, seq, args.current_phase, args.search_cursor ?? null,
       normalized.remaining_work, normalized.files_read, normalized.active_trace,
       normalized.tool_usage, args.checkpoint_reason ?? null]
    );
    db.run(
      `UPDATE finding_detail_runs SET status='RUNNING', current_phase=?, heartbeat_at=CURRENT_TIMESTAMP,
       updated_at=CURRENT_TIMESTAMP WHERE id=?`,
      [args.current_phase, args.detail_run_id]
    );
    db.close();
    return JSON.stringify({ checkpoint_id: result.lastInsertRowid, checkpoint_seq: seq, detail_run_id: args.detail_run_id });
  },
});

const auditGetFindingDetailContext = tool({
  description: "Load the complete DB context and latest checkpoint for exactly one finding. Resume from this state instead of re-running earlier work.",
  args: {
    finding_id: tool.schema.number().optional().describe("Finding ID"),
    detail_run_id: tool.schema.number().optional().describe("Detail run ID"),
  },
  async execute(args) {
    const db = getDb();
    let run = null;
    let finding = null;
    if (args.detail_run_id) {
      run = db.query("SELECT * FROM finding_detail_runs WHERE id=?").get(args.detail_run_id);
      if (run) finding = db.query("SELECT * FROM findings WHERE id=?").get(run.finding_id);
    } else if (args.finding_id) {
      finding = db.query("SELECT * FROM findings WHERE id=?").get(args.finding_id);
      run = db.query("SELECT * FROM finding_detail_runs WHERE finding_id=?").get(args.finding_id);
    } else {
      db.close();
      return JSON.stringify({ error: "Provide finding_id or detail_run_id" });
    }
    if (!finding) { db.close(); return JSON.stringify({ error: "Finding detail context not found" }); }
    const sinkChain = db.query("SELECT * FROM sink_chains WHERE finding_id=? ORDER BY step_order").all(finding.id);
    const candidates = db.query(
      `SELECT * FROM audit_candidates WHERE finding_id=? ORDER BY id`
    ).all(finding.id);
    const verification = db.query(
      "SELECT * FROM finding_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1"
    ).get(finding.id);
    const details = db.query("SELECT * FROM finding_report_details WHERE finding_id=?").get(finding.id);
    const artifact = db.query(
      "SELECT * FROM finding_report_artifacts WHERE finding_id=? ORDER BY content_version DESC LIMIT 1"
    ).get(finding.id);
    const checkpoint = run ? db.query(
      "SELECT * FROM finding_detail_checkpoints WHERE detail_run_id=? ORDER BY checkpoint_seq DESC LIMIT 1"
    ).get(run.id) : null;
    const project = db.query(
      `SELECT p.* FROM projects p JOIN audit_sessions s ON s.project_id=p.id WHERE s.id=?`
    ).get(finding.session_id);
    db.close();
    return JSON.stringify({ project, finding, detail_run: run, latest_checkpoint: checkpoint ?? null,
      sink_chain_steps: sinkChain, candidates, latest_verification: verification ?? null,
      report_details: details ?? null, latest_artifact: artifact ?? null });
  },
});

const auditSaveFindingReportDetails = tool({
  description: "Save Chinese product-facing facts for one verified finding. All JSON arguments contain arrays/objects and all narrative prose must be Chinese.",
  args: {
    detail_run_id: tool.schema.number().describe("Running per-finding detail run ID"),
    finding_id: tool.schema.number().describe("Finding ID owned by the run"),
    report_title: tool.schema.string().describe("Chinese vulnerability title"),
    component_name: tool.schema.string().describe("Affected component/service/module name; technical names may remain unchanged"),
    product_impact: tool.schema.string().describe("Chinese explanation of product/user/business impact"),
    affected_assets: tool.schema.string().describe("JSON array of affected products, modules, interfaces, data, or roles"),
    root_cause: tool.schema.string().describe("Chinese root cause tied to code evidence"),
    attacker_profile: tool.schema.string().describe("Chinese attacker identity and required privilege"),
    exploit_difficulty: tool.schema.string().describe("Chinese exploitation difficulty and reason"),
    preconditions: tool.schema.string().describe("JSON array of attack prerequisites"),
    attack_steps: tool.schema.string().describe("JSON array of ordered attack steps"),
    exploit_limitations: tool.schema.string().describe("JSON array of limitations and environmental constraints"),
    cia_impact: tool.schema.string().describe("JSON object describing confidentiality, integrity, and availability impact in Chinese"),
    affected_scope: tool.schema.string().describe("Chinese affected-version/component/tenant/data scope"),
    poc_explanation: tool.schema.string().optional().describe("Chinese safe PoC explanation"),
    expected_result: tool.schema.string().optional().describe("Deprecated compatibility field; use poc_expected_output"),
    poc_type: tool.schema.string().describe("EXECUTABLE_POC | STATIC_REPRO | REGRESSION_TEST | MANUAL_ONLY | NOT_REPRODUCED"),
    poc_validation_status: tool.schema.string().describe("NOT_RUN | SYNTAX_CHECKED | BUILT | EXECUTED | FAILED | BLOCKED"),
    poc_language: tool.schema.string().optional().describe("Markdown fence language for embedded PoC/test source, such as c, cpp, python, or bash"),
    poc_source: tool.schema.string().optional().describe("Complete PoC or regression-test source embedded directly in the Markdown report"),
    poc_setup_commands: tool.schema.string().optional().describe("JSON array of portable setup commands"),
    poc_build_commands: tool.schema.string().optional().describe("JSON array of portable build commands"),
    poc_run_commands: tool.schema.string().optional().describe("JSON array of executable verification commands"),
    poc_expected_output: tool.schema.string().optional().describe("Expected result; never present it as observed output"),
    poc_observed_output: tool.schema.string().optional().describe("Raw output captured from an actual EXECUTED or FAILED run only"),
    poc_negative_control_commands: tool.schema.string().optional().describe("JSON array of negative-control commands"),
    poc_negative_control_expected: tool.schema.string().optional().describe("Chinese explanation of the negative-control expected result"),
    poc_cleanup_commands: tool.schema.string().optional().describe("JSON array of portable cleanup commands"),
    poc_fixed_result: tool.schema.string().optional().describe("Chinese fixed-pass condition for REGRESSION_TEST"),
    poc_safety_notes: tool.schema.string().optional().describe("Chinese authorisation and harmlessness boundaries"),
    poc_execution_limitations: tool.schema.string().optional().describe("Chinese explanation of why execution was limited, blocked, or unavailable"),
    verification_steps: tool.schema.string().describe("JSON array of safe reproduction/verification steps"),
    immediate_mitigations: tool.schema.string().describe("JSON array of short-term mitigations"),
    required_fixes: tool.schema.string().describe("JSON array of P0/P1/P2 repair tasks with target, action, rationale, acceptance"),
    acceptance_criteria: tool.schema.string().describe("JSON array of repair acceptance criteria"),
    regression_tests: tool.schema.string().describe("JSON array of positive, negative, boundary, and authorization regression tests"),
    related_locations: tool.schema.string().describe("JSON array of related file/function locations"),
    related_finding_ids: tool.schema.string().optional().describe("JSON array of related finding IDs"),
    evidence_limitations: tool.schema.string().optional().describe("Chinese evidence limitations; required when verification is partial"),
  },
  async execute(args) {
    for (const field of ["report_title", "product_impact", "root_cause", "attacker_profile", "exploit_difficulty", "affected_scope"]) {
      const error = chineseTextError(field, args[field]);
      if (error) return JSON.stringify({ error });
    }
    if (!String(args.component_name ?? "").trim()) {
      return JSON.stringify({ error: "component_name is required" });
    }
    for (const field of ["poc_explanation", "poc_negative_control_expected", "poc_fixed_result",
      "poc_safety_notes", "poc_execution_limitations", "evidence_limitations"]) {
      const error = chineseTextError(field, args[field], false);
      if (error) return JSON.stringify({ error });
    }
    const jsonSpecs = {
      affected_assets: [[], "array"], preconditions: [[], "array"], attack_steps: [[], "array"],
      exploit_limitations: [[], "array"], cia_impact: [{}, "object"], verification_steps: [[], "array"],
      immediate_mitigations: [[], "array"], required_fixes: [[], "array"], acceptance_criteria: [[], "array"],
      regression_tests: [[], "array"], related_locations: [[], "array"], related_finding_ids: [[], "array"],
      poc_setup_commands: [[], "array"], poc_build_commands: [[], "array"], poc_run_commands: [[], "array"],
      poc_negative_control_commands: [[], "array"], poc_cleanup_commands: [[], "array"],
    };
    const normalized = {};
    const technicalJsonFields = new Set(["poc_setup_commands", "poc_build_commands", "poc_run_commands",
      "poc_negative_control_commands", "poc_cleanup_commands"]);
    for (const [field, [fallback, type]] of Object.entries(jsonSpecs)) {
      const result = parseJsonField(args[field], field, fallback, type);
      if (result.error) return JSON.stringify({ error: result.error });
      if (technicalJsonFields.has(field) && !result.parsed.every((item) => typeof item === "string" && item.trim())) {
        return JSON.stringify({ error: `${field} must contain only non-empty command strings` });
      }
      const languageError = technicalJsonFields.has(field) ? null : chineseJsonError(field, result.parsed);
      if (languageError) return JSON.stringify({ error: languageError });
      normalized[field] = result;
    }
    for (const requiredList of ["affected_assets", "attack_steps", "verification_steps", "required_fixes", "acceptance_criteria", "regression_tests"]) {
      if (!normalized[requiredList].parsed.length) {
        return JSON.stringify({ error: `${requiredList} must not be empty for a product-facing report` });
      }
    }
    if (!Object.keys(normalized.cia_impact.parsed).length) {
      return JSON.stringify({ error: "cia_impact must describe at least one impact dimension" });
    }
    const db = getDb();
    const run = db.query("SELECT * FROM finding_detail_runs WHERE id=?").get(args.detail_run_id);
    if (!run || run.finding_id !== args.finding_id) {
      db.close();
      return JSON.stringify({ error: "detail_run_id does not own finding_id" });
    }
    if (!["RUNNING", "RESUMING"].includes(run.status)) {
      db.close();
      return JSON.stringify({ error: `Detail run ${args.detail_run_id} is ${run.status}; details require a running run` });
    }
    const finding = db.query("SELECT * FROM findings WHERE id=?").get(args.finding_id);
    const verification = db.query(
      "SELECT * FROM finding_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1"
    ).get(args.finding_id);
    if (!finding || !verification) {
      db.close();
      return JSON.stringify({ error: "PoC details require an existing finding and verification conclusion" });
    }
    const pocQuality = validatePocDetails(args, normalized, finding, verification);
    if (pocQuality.error) {
      db.close();
      return JSON.stringify({ error: pocQuality.error });
    }
    db.run(
      `INSERT INTO finding_report_details
         (finding_id, report_title, component_name, product_impact, affected_assets, root_cause, attacker_profile,
          exploit_difficulty, preconditions, attack_steps, exploit_limitations, cia_impact,
          affected_scope, poc_explanation, expected_result,
          poc_type, poc_validation_status, poc_language, poc_source, poc_setup_commands, poc_build_commands,
          poc_run_commands, poc_expected_output, poc_observed_output, poc_negative_control_commands,
          poc_negative_control_expected, poc_cleanup_commands, poc_fixed_result, poc_safety_notes,
          poc_execution_limitations, verification_steps, immediate_mitigations,
          required_fixes, acceptance_criteria, regression_tests, related_locations,
          related_finding_ids, evidence_limitations, language, content_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'zh-CN', 1)
       ON CONFLICT(finding_id) DO UPDATE SET
         report_title=excluded.report_title, component_name=excluded.component_name,
         product_impact=excluded.product_impact,
         affected_assets=excluded.affected_assets, root_cause=excluded.root_cause,
         attacker_profile=excluded.attacker_profile, exploit_difficulty=excluded.exploit_difficulty,
         preconditions=excluded.preconditions, attack_steps=excluded.attack_steps,
         exploit_limitations=excluded.exploit_limitations, cia_impact=excluded.cia_impact,
         affected_scope=excluded.affected_scope, poc_explanation=excluded.poc_explanation,
         expected_result=excluded.expected_result, verification_steps=excluded.verification_steps,
         poc_type=excluded.poc_type, poc_validation_status=excluded.poc_validation_status,
         poc_language=excluded.poc_language, poc_source=excluded.poc_source,
         poc_setup_commands=excluded.poc_setup_commands, poc_build_commands=excluded.poc_build_commands,
         poc_run_commands=excluded.poc_run_commands, poc_expected_output=excluded.poc_expected_output,
         poc_observed_output=excluded.poc_observed_output,
         poc_negative_control_commands=excluded.poc_negative_control_commands,
         poc_negative_control_expected=excluded.poc_negative_control_expected,
         poc_cleanup_commands=excluded.poc_cleanup_commands, poc_fixed_result=excluded.poc_fixed_result,
         poc_safety_notes=excluded.poc_safety_notes,
         poc_execution_limitations=excluded.poc_execution_limitations,
         immediate_mitigations=excluded.immediate_mitigations, required_fixes=excluded.required_fixes,
         acceptance_criteria=excluded.acceptance_criteria, regression_tests=excluded.regression_tests,
         related_locations=excluded.related_locations, related_finding_ids=excluded.related_finding_ids,
         evidence_limitations=excluded.evidence_limitations, language='zh-CN',
         content_version=finding_report_details.content_version + 1,
         updated_at=CURRENT_TIMESTAMP`,
      [args.finding_id, args.report_title, String(args.component_name).trim(),
       args.product_impact, normalized.affected_assets.value,
       args.root_cause, args.attacker_profile, args.exploit_difficulty, normalized.preconditions.value,
       normalized.attack_steps.value, normalized.exploit_limitations.value, normalized.cia_impact.value,
       args.affected_scope, args.poc_explanation ?? null, pocQuality.expected || null,
       pocQuality.pocType, pocQuality.validationStatus, String(args.poc_language ?? "").trim().toLowerCase() || null,
       String(args.poc_source ?? "").trim() || null, normalized.poc_setup_commands.value,
       normalized.poc_build_commands.value, normalized.poc_run_commands.value, pocQuality.expected || null,
       String(args.poc_observed_output ?? "").trim() || null, normalized.poc_negative_control_commands.value,
       String(args.poc_negative_control_expected ?? "").trim() || null, normalized.poc_cleanup_commands.value,
       String(args.poc_fixed_result ?? "").trim() || null, String(args.poc_safety_notes ?? "").trim() || null,
       String(args.poc_execution_limitations ?? "").trim() || null,
       normalized.verification_steps.value, normalized.immediate_mitigations.value,
       normalized.required_fixes.value, normalized.acceptance_criteria.value,
       normalized.regression_tests.value, normalized.related_locations.value,
       normalized.related_finding_ids.value, args.evidence_limitations ?? null]
    );
    db.run(
      `UPDATE finding_detail_runs SET current_phase='产品修复方案已落库', heartbeat_at=CURRENT_TIMESTAMP,
       updated_at=CURRENT_TIMESTAMP WHERE id=?`, [args.detail_run_id]
    );
    const saved = db.query("SELECT finding_id, language, content_version FROM finding_report_details WHERE finding_id=?").get(args.finding_id);
    db.close();
    return JSON.stringify(saved);
  },
});

const auditGenerateFindingReport = tool({
  description: "Render exactly one verified finding as a Chinese Markdown product report. Individual finding HTML is intentionally unsupported.",
  args: {
    finding_id: tool.schema.number().describe("Finding ID"),
    output_dir: tool.schema.string().optional().describe("Defaults to {project_path}/audit-reports/findings"),
  },
  async execute(args, ctx) {
    const db = getDb();
    const finding = db.query("SELECT * FROM findings WHERE id=?").get(args.finding_id);
    if (!finding) { db.close(); return JSON.stringify({ error: `Finding ${args.finding_id} not found` }); }
    const run = db.query("SELECT * FROM finding_detail_runs WHERE finding_id=?").get(args.finding_id);
    if (!run || !["RUNNING", "RESUMING"].includes(run.status)) {
      db.close();
      return JSON.stringify({ error: "A running finding detail run is required before rendering" });
    }
    const verification = db.query(
      "SELECT * FROM finding_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1"
    ).get(args.finding_id);
    if (!verification) { db.close(); return JSON.stringify({ error: "missing_verification" }); }
    if (verification.verdict === "FALSE_POSITIVE" || verification.severity_action === "DROP") {
      db.close();
      return JSON.stringify({ error: "false_positive_no_individual_report", message: "误报不生成修复报告，请将 detail run 标记为 REJECTED 并保留排除原因。" });
    }
    const details = db.query("SELECT * FROM finding_report_details WHERE finding_id=?").get(args.finding_id);
    if (!details) { db.close(); return JSON.stringify({ error: "missing_finding_report_details" }); }
    if (!String(details.component_name ?? "").trim()) {
      db.close();
      return JSON.stringify({ error: "missing_component_name", message: "单漏洞报告必须标明受影响组件名称。" });
    }
    const storedPocNormalized = {};
    for (const field of ["poc_setup_commands", "poc_build_commands", "poc_run_commands",
      "poc_negative_control_commands", "poc_cleanup_commands"]) {
      const parsed = parseJsonField(details[field], field, [], "array");
      if (parsed.error) {
        db.close();
        return JSON.stringify({ error: "invalid_structured_poc", message: parsed.error });
      }
      storedPocNormalized[field] = parsed;
    }
    const storedPocQuality = validatePocDetails(details, storedPocNormalized, finding, verification);
    if (storedPocQuality.error) {
      db.close();
      return JSON.stringify({ error: "insufficient_poc_material", message: storedPocQuality.error });
    }
    const sinkSteps = db.query("SELECT * FROM sink_chains WHERE finding_id=? ORDER BY step_order").all(args.finding_id);
    const chainStatus = chainEvidenceStatus(sinkSteps);
    const reportSeverity = effectiveSeverity(finding, verification);
    if (["Critical", "High", "Medium"].includes(reportSeverity) && !chainStatus.complete) {
      db.close();
      return JSON.stringify({ error: "missing_evidence_chain", chain_quality: chainStatus });
    }
    const detailQuality = detailedEvidenceQuality(chainStatus.steps, reportSeverity);
    if (!detailQuality.complete) {
      db.close();
      return JSON.stringify({
        error: "insufficient_code_context",
        message: "中高危及以上报告的输入源和危险点必须包含函数名及至少 8 行非空代码，中间节点至少 5 行非空代码。",
        issues: detailQuality.issues,
      });
    }
    const session = db.query("SELECT * FROM audit_sessions WHERE id=?").get(finding.session_id);
    const project = db.query("SELECT * FROM projects WHERE id=?").get(session.project_id);
    let vulnerabilityId = String(finding.vuln_id ?? "").trim();
    if (!vulnerabilityId) {
      const prefix = { Critical: "C", High: "H", Medium: "M", Low: "L", Info: "I" }[reportSeverity] ?? "V";
      vulnerabilityId = `${prefix}-${String(finding.id).padStart(4, "0")}`;
      db.run("UPDATE findings SET vuln_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", [vulnerabilityId, finding.id]);
      finding.vuln_id = vulnerabilityId;
    }
    const markdown = generateFindingMarkdown(project, finding, verification, details, chainStatus.steps);
    if (!HAN_TEXT.test(markdown)) {
      db.close();
      return JSON.stringify({ error: "chinese_language_gate_failed" });
    }
    const outDir = args.output_dir
      ?? (project.path ? join(project.path, "audit-reports", "findings") : join(ctx.directory, "audit-reports", "findings"));
    mkdirSync(outDir, { recursive: true });
    const safeId = vulnerabilityId.replace(/[^A-Za-z0-9_.-]/g, "-");
    const componentSlug = reportTitleFileSlug(details.component_name, 48);
    const titleSlug = reportTitleFileSlug(details.report_title);
    const markdownPath = join(outDir, `${safeId}-${componentSlug}-${titleSlug}.md`);
    writeFileSync(markdownPath, markdown, "utf8");
    const contentHash = createHash("sha256").update(markdown).digest("hex");
    db.run(
      `INSERT INTO finding_report_artifacts
         (finding_id, content_version, content_hash, markdown_path, language_status)
       VALUES (?, ?, ?, ?, '中文校验通过')
       ON CONFLICT(finding_id, content_version) DO UPDATE SET
         content_hash=excluded.content_hash, markdown_path=excluded.markdown_path,
         language_status=excluded.language_status, generated_at=CURRENT_TIMESTAMP`,
      [finding.id, details.content_version, contentHash, markdownPath]
    );
    db.run(
      `UPDATE finding_detail_runs SET current_phase='单漏洞 Markdown 已生成', heartbeat_at=CURRENT_TIMESTAMP,
       updated_at=CURRENT_TIMESTAMP WHERE id=?`, [run.id]
    );
    db.close();
    return JSON.stringify({ finding_id: finding.id, vulnerability_id: vulnerabilityId,
      markdown: markdownPath, html: null, language: "中文", content_hash: contentHash });
  },
});

const auditFinishFindingDetailRun = tool({
  description: "Finalize, reject, or interrupt one per-finding run. COMPLETED requires a current Markdown artifact; REJECTED requires a false-positive DROP verification.",
  args: {
    detail_run_id: tool.schema.number().describe("Per-finding detail run ID"),
    status: tool.schema.string().describe("COMPLETED | REJECTED | INTERRUPTED | FAILED | SKIPPED"),
    reason: tool.schema.string().optional().describe("Chinese reason; required for every non-COMPLETED status"),
  },
  async execute(args) {
    const status = String(args.status ?? "").trim().toUpperCase();
    if (!["COMPLETED", "REJECTED", "INTERRUPTED", "FAILED", "SKIPPED"].includes(status)) {
      return JSON.stringify({ error: "Unsupported finding detail terminal status" });
    }
    if (status !== "COMPLETED") {
      const reasonError = chineseTextError("reason", args.reason);
      if (reasonError) return JSON.stringify({ error: reasonError });
    }
    const db = getDb();
    const run = db.query("SELECT * FROM finding_detail_runs WHERE id=?").get(args.detail_run_id);
    if (!run) { db.close(); return JSON.stringify({ error: `Detail run ${args.detail_run_id} not found` }); }
    const verification = db.query(
      "SELECT * FROM finding_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1"
    ).get(run.finding_id);
    if (status === "REJECTED" && (!verification || (verification.verdict !== "FALSE_POSITIVE" && verification.severity_action !== "DROP"))) {
      db.close();
      return JSON.stringify({ error: "REJECTED requires FALSE_POSITIVE or DROP verification" });
    }
    if (status === "COMPLETED") {
      const details = db.query(
        "SELECT content_version, poc_type, poc_validation_status FROM finding_report_details WHERE finding_id=?"
      ).get(run.finding_id);
      const artifact = details ? db.query(
        "SELECT id FROM finding_report_artifacts WHERE finding_id=? AND content_version=?"
      ).get(run.finding_id, details.content_version) : null;
      const hasStructuredPoc = details
        && POC_TYPES.has(String(details.poc_type ?? "").toUpperCase())
        && POC_VALIDATION_STATUSES.has(String(details.poc_validation_status ?? "").toUpperCase());
      if (!verification || !details || !artifact || !hasStructuredPoc) {
        db.close();
        return JSON.stringify({ error: "COMPLETED requires verification, structured PoC details, and current Markdown artifact" });
      }
    }
    const completedAt = ["COMPLETED", "REJECTED", "FAILED", "SKIPPED"].includes(status);
    db.run(
      `UPDATE finding_detail_runs SET status=?, status_reason=?, current_phase=?,
       interrupted_at=CASE WHEN ?='INTERRUPTED' THEN CURRENT_TIMESTAMP ELSE interrupted_at END,
       completed_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE completed_at END,
       heartbeat_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
      [status, args.reason ?? null,
       status === "COMPLETED" ? "报告完成" : status === "REJECTED" ? "误报已排除" : "任务已中断",
       status, completedAt ? 1 : 0, args.detail_run_id]
    );
    db.close();
    return JSON.stringify({ detail_run_id: args.detail_run_id, finding_id: run.finding_id, status });
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
  description: "Mark a session completed only after D1-D10 and every per-finding report run satisfy their terminal contracts.",
  args: {
    session_id: tool.schema.number().describe("Session ID to mark as completed"),
  },
  async execute(args) {
    const db = getDb();
    const session = db.query("SELECT id FROM audit_sessions WHERE id=?").get(args.session_id);
    if (!session) { db.close(); return JSON.stringify({ error: `Session ${args.session_id} not found` }); }
    const runs = db.query("SELECT id, dimension, status, status_reason FROM audit_agent_runs WHERE session_id=?").all(args.session_id);
    const expected = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
    const present = new Set(runs.map((run) => run.dimension));
    const missing = expected.filter((dimension) => !present.has(dimension));
    if (missing.length) {
      db.close();
      return JSON.stringify({ error: "missing_agent_runs", missing_dimensions: missing });
    }
    const terminal = new Set(["COMPLETED", "NOT_APPLICABLE", "FAILED", "SKIPPED"]);
    const unfinished = runs.filter((run) => !terminal.has(run.status));
    if (unfinished.length) {
      db.close();
      return JSON.stringify({
        error: "unfinished_agent_runs",
        agent_runs: unfinished.map((run) => ({ agent_run_id: run.id, dimension: run.dimension, status: run.status })),
      });
    }
    const missingReasons = runs.filter((run) => run.status !== "COMPLETED" && !String(run.status_reason ?? "").trim());
    if (missingReasons.length) {
      db.close();
      return JSON.stringify({ error: "missing_agent_status_reasons", agent_run_ids: missingReasons.map((run) => run.id) });
    }
    const findings = db.query("SELECT id FROM findings WHERE session_id=? ORDER BY id").all(args.session_id);
    const detailRuns = db.query("SELECT * FROM finding_detail_runs WHERE session_id=?").all(args.session_id);
    const detailRunMap = Object.fromEntries(detailRuns.map((run) => [run.finding_id, run]));
    const missingFindingRuns = findings.filter((finding) => !detailRunMap[finding.id]).map((finding) => finding.id);
    const unfinishedFindingRuns = detailRuns.filter((run) => !["COMPLETED", "REJECTED"].includes(run.status));
    if (missingFindingRuns.length || unfinishedFindingRuns.length) {
      db.close();
      return JSON.stringify({
        error: "unfinished_finding_detail_runs",
        missing_finding_ids: missingFindingRuns,
        detail_runs: unfinishedFindingRuns.map((run) => ({ id: run.id, finding_id: run.finding_id, status: run.status })),
      });
    }
    const missingCurrentArtifacts = db.query(
      `SELECT r.finding_id FROM finding_detail_runs r
       LEFT JOIN finding_report_details d ON d.finding_id=r.finding_id
       LEFT JOIN finding_report_artifacts a
         ON a.finding_id=r.finding_id AND a.content_version=d.content_version
       WHERE r.session_id=? AND r.status='COMPLETED' AND a.id IS NULL`
    ).all(args.session_id);
    if (missingCurrentArtifacts.length) {
      db.close();
      return JSON.stringify({ error: "missing_finding_markdown_reports",
        missing_finding_ids: missingCurrentArtifacts.map((row) => row.finding_id) });
    }
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

function effectiveSeverity(f, verification) {
  const current = normalizeSeverity(f.severity);
  const idx = SEVERITY_ORDER.indexOf(current);
  const action = verification?.severity_action;
  if (action === "DROP") return "Info";
  if (action === "DOWNGRADE_2") return SEVERITY_ORDER[Math.min(idx + 2, SEVERITY_ORDER.length - 1)];
  if (action === "DOWNGRADE_1") return SEVERITY_ORDER[Math.min(idx + 1, SEVERITY_ORDER.length - 1)];
  return current;
}

const REPORT_LABELS = {
  severity: { Critical: "严重", High: "高危", Medium: "中危", Low: "低危", Info: "提示" },
  verdict: { VERIFIED: "已核验", PARTIAL: "部分核验", SINK_ONLY: "仅确认危险点", FALSE_POSITIVE: "误报" },
  source: { TRUE_SOURCE: "真实外部输入", CONDITIONAL_SOURCE: "条件性输入", PSEUDO_SOURCE: "伪输入源", NO_SOURCE: "未找到输入源", NO_CHAIN: "无证据链" },
  sink: { CONFIRMED: "危险点已确认", UNCLEAR: "危险点不明确", NOT_FOUND: "未找到危险点" },
  sanitizer: { NONE: "未发现有效防护", BYPASSABLE: "防护可绕过", EFFECTIVE: "防护有效", UNKNOWN: "防护状态未知" },
  exploitability: { PRACTICAL: "可实际利用", CONDITIONAL: "满足条件后可利用", THEORETICAL: "仅理论可利用", NOT_EXPLOITABLE: "不可利用" },
  action: { KEEP: "保留", DOWNGRADE_1: "降低一级", DOWNGRADE_2: "降低两级", DROP: "排除" },
  run: { QUEUED: "等待执行", RUNNING: "执行中", RESUMING: "恢复执行中", CHECKPOINTED: "已保存断点", INTERRUPTED: "已中断", COMPLETED: "已完成", REJECTED: "误报已排除", NOT_APPLICABLE: "不适用", FAILED: "执行失败", SKIPPED: "已跳过" },
  candidate: { SINK: "危险点", CONTROL: "安全控制", CONFIG: "安全配置", MEMORY: "内存安全" },
};

function localized(group, value) {
  if (value === undefined || value === null || value === "") return "未记录";
  return REPORT_LABELS[group]?.[value] ?? String(value);
}

const STRUCTURED_KEY_LABELS = {
  priority: "优先级", target: "修改位置", action: "修复动作", rationale: "修复原因",
  acceptance: "验收要求", type: "类型", name: "名称", module: "模块", asset: "资产",
  requirement: "要求", evidence: "证据", step: "步骤", operation: "操作", result: "结果",
  level: "影响等级", impact: "影响说明", confidentiality: "机密性", integrity: "完整性",
  availability: "可用性", file_path: "文件", line_number: "行号", function: "函数",
  finding_id: "漏洞编号", description: "说明", condition: "条件", scope: "范围",
};

function structuredText(item) {
  if (item === undefined || item === null) return "未记录";
  if (["string", "number", "boolean"].includes(typeof item)) return String(item);
  if (Array.isArray(item)) return item.map(structuredText).join("；");
  return Object.entries(item)
    .map(([key, value]) => `${STRUCTURED_KEY_LABELS[key] ?? `字段 \`${key}\``}：${structuredText(value)}`)
    .join("；");
}

function markdownList(items, emptyText = "当前未记录。") {
  if (!Array.isArray(items) || !items.length) return `- ${emptyText}`;
  return items.map((item) => `- ${structuredText(item)}`).join("\n");
}

function reportTitleFileSlug(title, maxLength = 72) {
  const normalized = String(title ?? "")
    .normalize("NFKC")
    .replace(/[\u0000-\u001f\u007f/\\:*?"<>|]/g, "-")
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[.\s-]+|[.\s-]+$/g, "");
  const compact = Array.from(normalized).slice(0, maxLength).join("").replace(/[.\s-]+$/g, "");
  return compact || "未命名漏洞";
}

function evidenceJudgment(step) {
  const type = normalizeStepType(step.step_type);
  if (type === "Source") return "该节点承接攻击者可控输入；可控性已在本漏洞独立核验中确认。";
  if (type === "Sink") return "该节点执行危险操作；输入到达此处后会产生报告所述安全影响。";
  if (type === "Sanitizer") return "该节点执行安全检查；核验结果表明该检查缺失、覆盖不足或可被绕过。";
  return "该节点负责数据转换或跨函数传播，未切断从输入源到危险点的可达路径。";
}

function localizedConfidence(value) {
  const text = String(value ?? "").trim();
  if (!text) return "未记录";
  if (HAN_TEXT.test(text)) return text;
  const normalized = text.toUpperCase().replaceAll(" ", "_");
  return {
    VERIFIED: "已验证", HIGH: "高置信", HIGH_CONFIDENCE: "高置信",
    MEDIUM: "中置信", MEDIUM_CONFIDENCE: "中置信", LOW: "低置信",
    NEEDS_VERIFICATION: "需进一步验证", FALSE_POSITIVE: "误报已排除",
  }[normalized] ?? "已完成独立核验";
}

function markdownCodeBlock(content, language = "") {
  const text = String(content ?? "").replace(/\s+$/g, "");
  const runs = text.match(/`+/g) ?? [];
  const fence = "`".repeat(Math.max(3, ...runs.map((run) => run.length + 1)));
  const safeLanguage = /^[a-z0-9_+.#-]+$/i.test(String(language ?? "").trim())
    ? String(language).trim().toLowerCase()
    : "";
  return `${fence}${safeLanguage}\n${text}\n${fence}`;
}

function commandBlock(commands) {
  const values = Array.isArray(commands) ? commands.map((value) => String(value).trim()).filter(Boolean) : [];
  return values.length ? markdownCodeBlock(values.join("\n"), "bash") : "_无需执行额外命令。_";
}

function renderPocDetails(details) {
  const type = String(details.poc_type ?? "").toUpperCase();
  const status = String(details.poc_validation_status ?? "").toUpperCase();
  const typeLabel = {
    EXECUTABLE_POC: "可执行 PoC", STATIC_REPRO: "可执行静态复现",
    REGRESSION_TEST: "可执行回归测试", MANUAL_ONLY: "仅手工验证",
    NOT_REPRODUCED: "未复现",
  }[type] ?? "未分类";
  const statusLabel = {
    NOT_RUN: "未执行（仅审阅材料）", SYNTAX_CHECKED: "已完成语法检查，未运行",
    BUILT: "已构建，未运行", EXECUTED: "已实际执行并记录输出",
    FAILED: "执行失败并记录错误", BLOCKED: "受环境或授权边界阻塞",
  }[status] ?? "未记录";
  const setup = parseStoredJson(details.poc_setup_commands, []);
  const build = parseStoredJson(details.poc_build_commands, []);
  const run = parseStoredJson(details.poc_run_commands, []);
  const negative = parseStoredJson(details.poc_negative_control_commands, []);
  const cleanup = parseStoredJson(details.poc_cleanup_commands, []);
  const verificationSteps = parseStoredJson(details.verification_steps, []);
  const source = String(details.poc_source ?? "").trim();
  const expected = String(details.poc_expected_output ?? details.expected_result ?? "").trim();
  const observed = String(details.poc_observed_output ?? "").trim();
  const sourceSection = source
    ? `### 6.3 PoC / 测试源代码\n\n${markdownCodeBlock(source, details.poc_language)}`
    : `### 6.3 PoC / 测试源代码\n\n本验证类型不需要独立源代码，使用下方可执行命令完成核验。`;
  const actualSection = ["EXECUTED", "FAILED"].includes(status)
    ? markdownCodeBlock(observed, "console")
    : "未执行，因此没有实际运行输出。下述内容仅为预期结果，不代表已经在运行环境中观察到。";
  const fixedResult = details.poc_fixed_result
    ? `\n\n修复后通过条件：${details.poc_fixed_result}`
    : "";

  return `${details.poc_explanation || "以下验证材料仅用于获得明确授权的隔离测试环境，不应对生产数据或外部目标执行。"}

### 6.1 验证类型与证据状态

| 项目 | 结论 |
|------|------|
| 验证类型 | ${typeLabel} |
| 执行状态 | ${statusLabel} |
| 代码语言 | ${details.poc_language || "不适用"} |

- 安全边界：${details.poc_safety_notes || "未提供额外说明；执行前必须确认目标和环境已获得授权。"}
- 执行限制：${details.poc_execution_limitations || "未记录额外执行限制。"}

### 6.2 前置准备

${commandBlock(setup)}

${sourceSection}

### 6.4 构建与运行命令

构建命令：

${commandBlock(build)}

运行或核验命令：

${commandBlock(run)}

### 6.5 预期结果与实际记录

预期结果：${expected || "未形成可验证的预期结果。"}

实际记录：

${actualSection}${fixedResult}

### 6.6 负向对照

${commandBlock(negative)}

负向对照预期：${details.poc_negative_control_expected || "当前验证类型未提供负向对照。"}

### 6.7 复现步骤、清理与限制

复现步骤：

${markdownList(verificationSteps)}

清理命令：

${commandBlock(cleanup)}

限制说明：${details.poc_execution_limitations || "未记录额外限制。"}`;
}

function generateFindingMarkdown(project, finding, verification, details, sinkSteps) {
  const severity = effectiveSeverity(finding, verification);
  const affectedAssets = parseStoredJson(details.affected_assets, []);
  const preconditions = parseStoredJson(details.preconditions, []);
  const attackSteps = parseStoredJson(details.attack_steps, []);
  const limitations = parseStoredJson(details.exploit_limitations, []);
  const cia = parseStoredJson(details.cia_impact, {});
  const mitigations = parseStoredJson(details.immediate_mitigations, []);
  const fixes = parseStoredJson(details.required_fixes, []);
  const acceptance = parseStoredJson(details.acceptance_criteria, []);
  const regression = parseStoredJson(details.regression_tests, []);
  const locations = parseStoredJson(details.related_locations, []);
  const related = parseStoredJson(details.related_finding_ids, []);
  const id = finding.vuln_id || `V-${finding.id}`;
  const sourceToSink = sinkSteps.map((step) => {
    const type = normalizeStepType(step.step_type);
    const typeZh = { Source: "输入源", Transform: "传播/转换", Sanitizer: "安全检查", Sink: "危险点" }[type] ?? "证据节点";
    const functionName = String(step.function_name ?? "").trim();
    return `${typeZh}(${stepLocation(step)}${functionName ? ` · ${functionName}` : ""})`;
  }).join(" → ");
  const evidenceBlocks = sinkSteps.map((step, index) => {
    const type = normalizeStepType(step.step_type);
    const typeZh = { Source: "输入源", Transform: "传播/转换", Sanitizer: "安全检查", Sink: "危险点" }[type] ?? "证据节点";
    const snippet = String(step.code_snippet ?? "").trim();
    const functionName = String(step.function_name ?? "").trim() || "未记录（需补充）";
    const contextRange = step.context_start_line && step.context_end_line
      ? `${step.file_path ?? "未记录文件"}:${step.context_start_line}-${step.context_end_line}`
      : "未单独记录上下文行范围";
    const code = snippet
      ? `\n\n\`\`\`${langForPath(step.file_path)}\n${snippet}\n\`\`\``
      : "\n\n_该节点未保存代码片段，请按所列文件与行号复核。_";
    return `### ${index + 1}. ${typeZh}\n\n- 位置：\`${stepLocation(step)}\`（组件：\`${details.component_name}\`；相关函数：\`${functionName}\`）\n- 代码范围：\`${contextRange}\`\n- 安全判断：${evidenceJudgment(step)}${code}`;
  }).join("\n\n");
  const relatedText = related.length ? related.map((value) => `\`${value}\``).join("、") : "无";

  return `# 【${reportProjectName(project)}】【${id}】${details.report_title}

| 属性 | 内容 |
|------|------|
| 组件名称 | ${escapeMdCell(details.component_name)} |
| 风险等级 | ${localized("severity", severity)} |
| 漏洞类型 | ${escapeMdCell(finding.vuln_type ?? "未分类")} |
| CWE | ${escapeMdCell(finding.cwe ?? "未记录")} |
| 置信度 | ${escapeMdCell(localizedConfidence(finding.confidence))} |
| 核验结论 | ${localized("verdict", verification.verdict)}；${localized("source", verification.source_status)}；${localized("sink", verification.sink_status)} |
| 可利用性 | ${localized("exploitability", verification.exploitability)} |
| 主位置 | \`${escapeMdCell(finding.file_path ?? "未记录")}${finding.line_number ? `:${finding.line_number}` : ""}\` |

## 一、风险与产品影响

${details.product_impact}

受影响资产：

${markdownList(affectedAssets)}

影响范围：${details.affected_scope}

## 二、事实与根因

${details.root_cause}

- 攻击者条件：${details.attacker_profile}
- 利用难度：${details.exploit_difficulty}
- 防护判断：${localized("sanitizer", verification.sanitizer_status)}

## 三、代码与证据链

数据流：\`${sourceToSink || "证据链未记录"}\`

${evidenceBlocks || "当前未记录可展示的代码证据节点。"}

## 四、攻击前置条件与利用场景

前置条件：

${markdownList(preconditions, "无额外前置条件。")}

攻击步骤：

${markdownList(attackSteps)}

利用限制：

${markdownList(limitations, "未发现额外利用限制。")}

## 五、安全影响与受影响范围

${Object.entries(cia).map(([key, value]) => `- ${STRUCTURED_KEY_LABELS[key] ?? `影响维度 \`${key}\``}：${structuredText(value)}`).join("\n")}

${details.affected_scope}

## 六、安全核验与 PoC

${renderPocDetails(details)}

## 七、修复方案

### 立即缓解

${markdownList(mitigations, "在正式修复上线前限制相关入口的访问权限并加强日志监控。")}

### 必须实施的修复

${markdownList(fixes)}

## 八、验收标准与回归测试

验收标准：

${markdownList(acceptance)}

回归测试：

${markdownList(regression)}

## 九、关联位置与证据边界

关联位置：

${markdownList(locations, "除主位置外未确认其他受影响位置。")}

- 关联漏洞：${relatedText}
- 证据边界：${details.evidence_limitations || "本报告结论以当前代码版本、已读取配置和已确认调用链为边界；环境差异需在上线前复核。"}
`;
}

function severityBadge(s) {
  const normalized = normalizeSeverity(s);
  const colors = { Critical: "#d32f2f", High: "#f57c00", Medium: "#fbc02d", Low: "#388e3c", Info: "#1976d2" };
  return `<span style="background:${colors[normalized]??'#888'};color:#fff;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:bold">${normalized}</span>`;
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
  const reportable = reportableSinkSteps(steps);
  const source = reportable.find(s => normalizeStepType(s.step_type) === "Source");
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
  const chainStatus = chainEvidenceStatus(steps);
  if (!chainStatus.hasEvidence) return "NO_CHAIN";
  const sourceStatus = sourceStatusForSteps(chainStatus.steps);
  const hasSink = chainStatus.hasSink;
  if (sourceStatus === "TRUE_SOURCE" && hasSink) return "VERIFIED";
  if (sourceStatus === "NO_SOURCE" && hasSink) return "SINK_ONLY";
  if (!hasSink) return "PARTIAL";
  return sourceStatus;
}

function verificationSourceStatus(steps, verification) {
  const chainStatus = chainEvidenceStatus(steps);
  return verification?.source_status || (chainStatus.hasEvidence ? sourceStatusForSteps(chainStatus.steps) : "NO_CHAIN");
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
    const steps = reportableSinkSteps(sinkMap[f.id] ?? []);
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
    const steps = reportableSinkSteps(sinkMap[f.id] ?? []);
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

function buildCandidateCoverageMd(coverageRows = [], uncheckedRows = []) {
  if (!coverageRows.length && !uncheckedRows.length) return "";
  let md = `## Candidate 覆盖与 Known Gaps\n\n`;
  if (coverageRows.length) {
    md += `| 类型 | 维度 | 候选 | 已分类 | 未完成 | 漏洞 | 高危证据链 | 覆盖 |\n`;
    md += `|------|------|------|--------|--------|------|------------|------|\n`;
    for (const row of coverageRows) {
      const highPath = row.high_risk > 0 ? `${row.high_path_complete}/${row.high_risk}` : "0/0";
      const covered = row.candidates > 0 && row.unchecked === 0 &&
        (row.high_risk === 0 || row.high_path_complete === row.high_risk);
      md += `| ${escapeMdCell(row.candidate_kind)} | ${escapeMdCell(row.dimension)} | ${row.candidates} | ${row.triaged} | ${row.unchecked} | ${row.findings} | ${highPath} | ${covered ? "YES" : "NO"} |\n`;
    }
    md += `\n`;
  }
  if (uncheckedRows.length) {
    md += `### 未完成候选\n\n`;
    md += `| 类型 | 维度 | 规则 | 位置 | 状态 | 原因 |\n`;
    md += `|------|------|------|------|------|------|\n`;
    for (const row of uncheckedRows) {
      const loc = row.file_path ? `${row.file_path}${row.line_number ? `:${row.line_number}` : ""}` : "-";
      md += `| ${escapeMdCell(row.candidate_kind)} | ${escapeMdCell(row.dimension)} | ${escapeMdCell(row.rule_id ?? row.candidate_type)} | \`${escapeMdCell(loc)}\` | ${escapeMdCell(row.status)} | ${escapeMdCell(row.reason)} |\n`;
    }
    md += `\n`;
  }
  return md;
}

function buildCandidateCoverageHtml(coverageRows = [], uncheckedRows = []) {
  if (!coverageRows.length && !uncheckedRows.length) return "";
  const coverageTable = coverageRows.length ? `
    <table style="border-collapse:collapse;width:100%;font-size:0.9em;margin:16px 0;background:#fff">
      <thead><tr style="background:#f1f3f5">
        <th style="text-align:left;padding:8px;border:1px solid #ddd">类型</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">维度</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">候选</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">已分类</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">未完成</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">漏洞</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">高危证据链</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">覆盖</th>
      </tr></thead>
      <tbody>
        ${coverageRows.map(row => {
          const highPath = row.high_risk > 0 ? `${row.high_path_complete}/${row.high_risk}` : "0/0";
          const covered = row.candidates > 0 && row.unchecked === 0 &&
            (row.high_risk === 0 || row.high_path_complete === row.high_risk);
          return `<tr>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.candidate_kind ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.dimension ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd">${row.candidates}</td>
            <td style="padding:8px;border:1px solid #ddd">${row.triaged}</td>
            <td style="padding:8px;border:1px solid #ddd">${row.unchecked}</td>
            <td style="padding:8px;border:1px solid #ddd">${row.findings}</td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(highPath)}</td>
            <td style="padding:8px;border:1px solid #ddd">${covered ? "YES" : "NO"}</td>
          </tr>`;
        }).join("\n")}
      </tbody>
    </table>` : "";

  const uncheckedTable = uncheckedRows.length ? `
    <h3>未完成候选</h3>
    <table style="border-collapse:collapse;width:100%;font-size:0.9em;margin:16px 0;background:#fff">
      <thead><tr style="background:#fff8e8">
        <th style="text-align:left;padding:8px;border:1px solid #ddd">类型</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">维度</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">规则</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">位置</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">状态</th>
        <th style="text-align:left;padding:8px;border:1px solid #ddd">原因</th>
      </tr></thead>
      <tbody>
        ${uncheckedRows.map(row => {
          const loc = row.file_path ? `${row.file_path}${row.line_number ? `:${row.line_number}` : ""}` : "-";
          return `<tr>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.candidate_kind ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.dimension ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.rule_id ?? row.candidate_type ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd"><code>${escapeHtml(loc)}</code></td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.status ?? "-")}</td>
            <td style="padding:8px;border:1px solid #ddd">${escapeHtml(row.reason ?? "-")}</td>
          </tr>`;
        }).join("\n")}
      </tbody>
    </table>` : "";

  return `<h2>Candidate 覆盖与 Known Gaps</h2>${coverageTable}${uncheckedTable}`;
}

function buildAgentRunsMd(agentRuns = []) {
  if (!agentRuns.length) return "";
  let md = `## D1-D10 Agent 执行矩阵\n\n`;
  md += `| 维度 | 轮次 | Agent | 状态 | 阶段 | 未执行/异常原因 |\n`;
  md += `|------|------|-------|------|------|-----------------|\n`;
  for (const run of agentRuns) {
    md += `| ${escapeMdCell(run.dimension)} | ${run.round_number} | ${escapeMdCell(run.agent_source)} | ${escapeMdCell(run.status)} | ${escapeMdCell(run.current_phase ?? "-")} | ${escapeMdCell(run.status_reason ?? "-")} |\n`;
  }
  return `${md}\n`;
}

function buildAgentRunsHtml(agentRuns = []) {
  if (!agentRuns.length) return "";
  const rows = agentRuns.map((run) => `<tr>
    <td style="padding:8px;border:1px solid #ddd">${escapeHtml(run.dimension)}</td>
    <td style="padding:8px;border:1px solid #ddd">${run.round_number}</td>
    <td style="padding:8px;border:1px solid #ddd">${escapeHtml(run.agent_source)}</td>
    <td style="padding:8px;border:1px solid #ddd">${escapeHtml(run.status)}</td>
    <td style="padding:8px;border:1px solid #ddd">${escapeHtml(run.current_phase ?? "-")}</td>
    <td style="padding:8px;border:1px solid #ddd">${escapeHtml(run.status_reason ?? "-")}</td>
  </tr>`).join("\n");
  return `<h2>D1-D10 Agent 执行矩阵</h2>
  <table style="border-collapse:collapse;width:100%;font-size:0.9em;margin:16px 0;background:#fff">
    <thead><tr style="background:#f1f3f5">
      <th style="text-align:left;padding:8px;border:1px solid #ddd">维度</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">轮次</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">Agent</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">状态</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">阶段</th>
      <th style="text-align:left;padding:8px;border:1px solid #ddd">未执行/异常原因</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function buildSinkChainMd(steps, f, verification) {
  const reportableSteps = reportableSinkSteps(steps);
  const displaySteps = reportableSteps.length ? reportableSteps : fallbackFlowSteps(f);
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
  const reportableSteps = reportableSinkSteps(steps);
  const displaySteps = reportableSteps.length ? reportableSteps : fallbackFlowSteps(f);
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

function generateMarkdown(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap = {}, candidateCoverage = [], uncheckedCandidates = [], agentRuns = []) {
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

  md += buildAgentRunsMd(agentRuns);
  md += buildVerificationSummaryMd(orderedFindings, sinkMap, verificationMap);
  md += buildCandidateCoverageMd(candidateCoverage, uncheckedCandidates);

  md += `## 漏洞详情\n\n`;
  for (const f of orderedFindings) {
    const steps = reportableSinkSteps(sinkMap[f.id] ?? []);
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

function generateHtml(session, project, findings, sinkMap, attackChains, chainSteps, verificationMap = {}, candidateCoverage = [], uncheckedCandidates = [], agentRuns = []) {
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
    const steps = reportableSinkSteps(sinkMap[f.id] ?? []);
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

  ${buildAgentRunsHtml(agentRuns)}
  ${buildVerificationSummaryHtml(orderedFindings, sinkMap, verificationMap)}
  ${buildCandidateCoverageHtml(candidateCoverage, uncheckedCandidates)}

  <h2 style="border-bottom:2px solid #333;padding-bottom:8px;margin-top:40px">漏洞详情</h2>
  ${findingsHtml}
  ${attackHtml}

  <footer style="margin-top:48px;padding-top:16px;border-top:1px solid #ddd;color:#888;font-size:0.85em">
    Generated by audit-db plugin · ${date}
  </footer>
</body>
</html>`;
}

function reportChineseOrFallback(value, fallback) {
  const text = String(value ?? "").trim();
  return !text || (!HAN_TEXT.test(text) && !looksTechnicalOnly(text)) ? fallback : text;
}

function generateReportIndexMarkdown(session, project, findings, verificationMap, detailRunMap, artifactMap, candidateCoverage, agentRuns, indexDir) {
  const active = reportOrderedFindings(
    findings.filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED"),
    verificationMap,
  );
  const rejected = findings.filter((finding) => detailRunMap[finding.id]?.status === "REJECTED");
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of active) counts[effectiveSeverity(finding, verificationMap[finding.id])] += 1;
  let md = `# ${reportProjectName(project)} 安全审计合并报告\n\n`;
  md += `- 审计会话：\`${session.id}\`\n`;
  md += `- 审计模式：\`${session.mode ?? "未记录"}\`\n`;
  md += `- 审计开始时间：${session.started_at ?? "未记录"}\n`;
  md += `- 已确认漏洞：${active.length}\n`;
  md += `- 已排除误报：${rejected.length}\n\n`;
  md += `## 风险统计\n\n| 等级 | 数量 |\n|------|------|\n`;
  for (const severity of SEVERITY_ORDER) md += `| ${localized("severity", severity)} | ${counts[severity]} |\n`;
  md += `\n## 单漏洞报告\n\n| 编号 | 组件名称 | 漏洞名称 | 风险等级 | 核验状态 | 报告 |\n|------|----------|----------|----------|----------|------|\n`;
  for (const finding of active) {
    const artifact = artifactMap[finding.id];
    const title = reportChineseOrFallback(finding.report_title ?? finding.title, `漏洞记录 ${finding.id}`);
    const path = artifact?.markdown_path
      ? relative(indexDir, artifact.markdown_path).replaceAll("\\", "/")
      : "";
    const anchor = `finding-${String(finding.vuln_id ?? finding.id).replace(/[^A-Za-z0-9_.-]/g, "-").toLowerCase()}`;
    const links = path ? `[本页详情](#${anchor}) / [独立 Markdown](${path})` : `[本页详情](#${anchor})`;
    md += `| ${escapeMdCell(finding.vuln_id ?? finding.id)} | ${escapeMdCell(finding.component_name ?? "未记录")} | ${escapeMdCell(title)} | ${localized("severity", effectiveSeverity(finding, verificationMap[finding.id]))} | 已完成独立核验 | ${links} |\n`;
  }
  if (!active.length) md += `| - | - | 当前没有通过核验的漏洞 | - | - | - |\n`;
  md += `\n## 已排除记录\n\n`;
  if (!rejected.length) {
    md += `本次没有被判定为误报的记录。\n\n`;
  } else {
    md += `| 数据库编号 | 原始标题 | 排除原因 |\n|------------|----------|----------|\n`;
    for (const finding of rejected) {
      const run = detailRunMap[finding.id];
      const title = reportChineseOrFallback(finding.report_title ?? finding.title, `漏洞记录 ${finding.id}`);
      md += `| ${finding.id} | ${escapeMdCell(title)} | ${escapeMdCell(reportChineseOrFallback(run.status_reason, "经独立核验后不满足漏洞成立条件"))} |\n`;
    }
    md += `\n`;
  }
  md += `## D1-D10 执行状态\n\n| 维度 | Agent | 状态 | 说明 |\n|------|-------|------|------|\n`;
  for (const run of agentRuns) {
    md += `| ${run.dimension} | ${escapeMdCell(run.agent_source)} | ${localized("run", run.status)} | ${escapeMdCell(reportChineseOrFallback(run.status_reason, run.status === "COMPLETED" ? "检测已完成" : "原因已记录在数据库"))} |\n`;
  }
  md += `\n## 候选覆盖概览\n\n| 候选类型 | 维度 | 总数 | 已处置 | 待处置 | 已确认漏洞 |\n|----------|------|------|--------|--------|------------|\n`;
  for (const row of candidateCoverage) {
    md += `| ${localized("candidate", row.candidate_kind)} | ${row.dimension ?? "-"} | ${row.candidates} | ${row.triaged} | ${row.unchecked} | ${row.findings} |\n`;
  }
  if (!candidateCoverage.length) md += `| - | - | 0 | 0 | 0 | 0 |\n`;
  md += `\n## 漏洞详细内容\n\n以下内容与对应的独立 Markdown 报告保持一致，包含完整代码证据、验证材料、修复方案和回归测试。\n`;
  if (!active.length) {
    md += `\n本次没有通过独立核验的漏洞。\n`;
  }
  for (const finding of active) {
    const artifact = artifactMap[finding.id];
    const anchor = `finding-${String(finding.vuln_id ?? finding.id).replace(/[^A-Za-z0-9_.-]/g, "-").toLowerCase()}`;
    md += `\n<a id="${anchor}"></a>\n\n---\n\n${String(artifact.markdown_content ?? "").trim()}\n`;
  }
  return `${md}\n`;
}

function generateReportIndexHtml(session, project, findings, verificationMap, detailRunMap, artifactMap) {
  const active = findings.filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED");
  const rejected = findings.filter((finding) => detailRunMap[finding.id]?.status === "REJECTED");
  const rows = active.map((finding) => {
    const title = reportChineseOrFallback(finding.report_title ?? finding.title, `漏洞记录 ${finding.id}`);
    const artifact = artifactMap[finding.id];
    return `<tr><td>${escapeHtml(finding.vuln_id ?? finding.id)}</td><td>${escapeHtml(finding.component_name ?? "未记录")}</td><td>${escapeHtml(title)}</td><td>${escapeHtml(localized("severity", effectiveSeverity(finding, verificationMap[finding.id])))}</td><td>已完成独立核验</td><td>${artifact?.markdown_path ? `<a href="${escapeHtml(artifact.markdown_path)}">查看 Markdown</a>` : "未生成"}</td></tr>`;
  }).join("\n") || `<tr><td colspan="6">当前没有通过核验的漏洞</td></tr>`;
  const rejectedRows = rejected.map((finding) => `<li>漏洞记录 ${finding.id}：${escapeHtml(reportChineseOrFallback(detailRunMap[finding.id]?.status_reason, "经独立核验后不满足漏洞成立条件"))}</li>`).join("\n") || "<li>无</li>";
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>${escapeHtml(reportProjectName(project))} 安全审计报告索引</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#202124}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:9px;text-align:left}th{background:#f3f5f7}a{color:#165dff}</style></head><body><h1>${escapeHtml(reportProjectName(project))} 安全审计报告索引</h1><p>审计会话：${session.id}；已确认漏洞：${active.length}；已排除误报：${rejected.length}。</p><h2>单漏洞报告</h2><table><thead><tr><th>编号</th><th>组件名称</th><th>漏洞名称</th><th>风险等级</th><th>核验状态</th><th>报告</th></tr></thead><tbody>${rows}</tbody></table><h2>已排除记录</h2><ul>${rejectedRows}</ul><p>详细的检测覆盖、Agent 状态和候选处置数据请查看同目录 Markdown 索引。</p></body></html>`;
}

const auditGenerateReport = tool({
  description: "Generate index.md as a Chinese merged full report containing every confirmed finding body, plus a lightweight index.html. Individual finding reports remain Markdown-only.",
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

    const agentRuns = db.query(
      `SELECT * FROM audit_agent_runs WHERE session_id=?
       ORDER BY CAST(SUBSTR(dimension, 2) AS INTEGER), round_number`
    ).all(args.session_id);
    const expectedDimensions = Array.from({ length: 10 }, (_, index) => `D${index + 1}`);
    const seenDimensions = new Set(agentRuns.map((run) => run.dimension));
    const missingDimensions = expectedDimensions.filter((dimension) => !seenDimensions.has(dimension));
    if (missingDimensions.length) {
      db.close();
      return JSON.stringify({
        error: "missing_agent_runs",
        message: "Final report requires a durable execution record for every D1-D10 agent.",
        missing_dimensions: missingDimensions,
      });
    }

    const terminalStatuses = new Set(["COMPLETED", "NOT_APPLICABLE", "FAILED", "SKIPPED"]);
    const unfinishedRuns = agentRuns.filter((run) => !terminalStatuses.has(run.status));
    if (unfinishedRuns.length) {
      db.close();
      return JSON.stringify({
        error: "unfinished_agent_runs",
        message: "Resume interrupted/running agents from their latest checkpoint before final report generation.",
        agent_runs: unfinishedRuns.map((run) => ({
          agent_run_id: run.id,
          dimension: run.dimension,
          round_number: run.round_number,
          status: run.status,
          current_phase: run.current_phase,
        })),
      });
    }

    const unreasonedRuns = agentRuns.filter((run) =>
      run.status !== "COMPLETED" && !String(run.status_reason ?? "").trim()
    );
    if (unreasonedRuns.length) {
      db.close();
      return JSON.stringify({
        error: "missing_agent_status_reasons",
        message: "Every non-completed agent run must record why it was not completed normally.",
        agent_run_ids: unreasonedRuns.map((run) => run.id),
      });
    }

    const findings = db.query(
      `SELECT f.*, d.report_title, d.component_name, d.poc_type, d.poc_validation_status,
              d.content_version AS report_content_version
       FROM findings f LEFT JOIN finding_report_details d ON d.finding_id=f.id
       WHERE f.session_id=? ORDER BY
         CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         f.id`
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

    const detailRuns = db.query(
      "SELECT * FROM finding_detail_runs WHERE session_id=? ORDER BY finding_id"
    ).all(args.session_id);
    const detailRunMap = Object.fromEntries(detailRuns.map((run) => [run.finding_id, run]));
    const missingDetailRuns = findings.filter((finding) => !detailRunMap[finding.id]).map((finding) => finding.id);
    if (missingDetailRuns.length) {
      db.close();
      return JSON.stringify({
        error: "missing_finding_detail_runs",
        message: "每个数据库漏洞都必须单独启动 audit-verification Agent。",
        missing_finding_ids: missingDetailRuns,
      });
    }
    const unfinishedDetailRuns = detailRuns.filter((run) => !["COMPLETED", "REJECTED"].includes(run.status));
    if (unfinishedDetailRuns.length) {
      db.close();
      return JSON.stringify({
        error: "unfinished_finding_detail_runs",
        message: "从逐漏洞断点继续执行，不得重新开始核验。",
        runs: unfinishedDetailRuns.map((run) => ({ detail_run_id: run.id, finding_id: run.finding_id,
          status: run.status, current_phase: run.current_phase })),
      });
    }
    const invalidRejectedRuns = detailRuns.filter((run) => {
      if (run.status !== "REJECTED") return false;
      const verification = verificationMap[run.finding_id];
      return !run.status_reason || !verification
        || (verification.verdict !== "FALSE_POSITIVE" && verification.severity_action !== "DROP");
    });
    if (invalidRejectedRuns.length) {
      db.close();
      return JSON.stringify({ error: "invalid_rejected_finding_runs",
        detail_run_ids: invalidRejectedRuns.map((run) => run.id) });
    }

    const missingComponents = findings
      .filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED" && !String(finding.component_name ?? "").trim())
      .map((finding) => finding.id);
    if (missingComponents.length) {
      db.close();
      return JSON.stringify({ error: "missing_component_names",
        message: "每个确认漏洞必须标明受影响组件名称并重新生成当前版本报告。",
        missing_finding_ids: missingComponents });
    }

    const missingPocMaterials = findings
      .filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED"
        && (!POC_TYPES.has(String(finding.poc_type ?? "").toUpperCase())
          || !POC_VALIDATION_STATUSES.has(String(finding.poc_validation_status ?? "").toUpperCase())))
      .map((finding) => finding.id);
    if (missingPocMaterials.length) {
      db.close();
      return JSON.stringify({
        error: "insufficient_poc_material",
        message: "每个确认漏洞必须保存结构化验证类型与执行状态，并重新生成内嵌 PoC 的当前版本报告。",
        missing_finding_ids: missingPocMaterials,
      });
    }

    const artifacts = db.query(
      `SELECT a.* FROM finding_report_artifacts a
       JOIN findings f ON f.id=a.finding_id
       JOIN finding_report_details d ON d.finding_id=f.id AND d.content_version=a.content_version
       WHERE f.session_id=?`
    ).all(args.session_id);
    const artifactMap = Object.fromEntries(artifacts.map((artifact) => [artifact.finding_id, artifact]));
    const missingArtifacts = findings
      .filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED" && !artifactMap[finding.id])
      .map((finding) => finding.id);
    if (missingArtifacts.length) {
      db.close();
      return JSON.stringify({
        error: "missing_finding_markdown_reports",
        message: "已确认漏洞必须先生成当前版本的中文单漏洞 Markdown。",
        missing_finding_ids: missingArtifacts,
      });
    }
    const unreadableArtifacts = [];
    for (const finding of findings.filter((item) => detailRunMap[item.id]?.status === "COMPLETED")) {
      const artifact = artifactMap[finding.id];
      if (!artifact?.markdown_path || !existsSync(artifact.markdown_path)) {
        unreadableArtifacts.push({ finding_id: finding.id, reason: "markdown_file_missing" });
        continue;
      }
      try {
        artifactMap[finding.id] = {
          ...artifact,
          markdown_content: readFileSync(artifact.markdown_path, "utf8"),
        };
      } catch (error) {
        unreadableArtifacts.push({ finding_id: finding.id, reason: String(error?.message ?? error) });
      }
    }
    if (unreadableArtifacts.length) {
      db.close();
      return JSON.stringify({
        error: "unreadable_finding_markdown_reports",
        message: "index.md 必须合并每个确认漏洞的完整正文；请恢复对应逐漏洞 run 并重新生成缺失报告。",
        reports: unreadableArtifacts,
      });
    }

    const missingEvidenceChains = findings
      .map((f) => {
        const verification = verificationMap[f.id];
        const chainStatus = chainEvidenceStatus(sinkMap[f.id] ?? []);
        return {
          finding_id: f.id,
          title: f.title,
          severity: effectiveSeverity(f, verification),
          chain_quality: {
            has_evidence: chainStatus.hasEvidence,
            has_source: chainStatus.hasSource,
            has_sink: chainStatus.hasSink,
            complete: chainStatus.complete,
          },
        };
      })
      .filter((row) => ["Critical", "High", "Medium"].includes(row.severity) && !row.chain_quality.complete);
    if (missingEvidenceChains.length && !args.allow_unverified) {
      db.close();
      return JSON.stringify({
        error: "missing_evidence_chains",
        message: "中高危及以上漏洞必须有可用的 Source-to-Sink 证据链；请恢复对应逐漏洞 run，读取 detail context 后补齐 sink_chain_steps。",
        findings: findings.length,
        missing_finding_ids: missingEvidenceChains.map((row) => row.finding_id),
        missing_evidence_chains: missingEvidenceChains,
      });
    }

    const candidateCoverage = db.query(
      `SELECT
         candidate_kind,
         dimension,
         COUNT(*) AS candidates,
         SUM(CASE WHEN status NOT IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS triaged,
         SUM(CASE WHEN status IN ('OPEN','TIMEOUT') THEN 1 ELSE 0 END) AS unchecked,
         SUM(CASE WHEN status IN ('EXCLUDED_TEST','EXCLUDED_VENDOR') THEN 1 ELSE 0 END) AS excluded,
         SUM(CASE WHEN status='TRACED_VULN' THEN 1 ELSE 0 END) AS findings,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H') THEN 1 ELSE 0 END) AS high_risk,
         SUM(CASE WHEN UPPER(COALESCE(risk,'')) IN ('CRITICAL','HIGH','C','H')
                   AND path_status IN ('COMPLETE','NOT_REQUIRED') THEN 1 ELSE 0 END) AS high_path_complete
       FROM audit_candidates
       WHERE session_id=?
       GROUP BY candidate_kind, dimension
       ORDER BY candidate_kind, dimension`
    ).all(args.session_id);

    db.close();

    // Determine output directory
    const outDir = args.output_dir
      ?? (project.path ? join(project.path, "audit-reports") : join(ctx.directory, "audit-reports"));
    mkdirSync(outDir, { recursive: true });

    const mdPath   = join(outDir, "index.md");
    const htmlPath = join(outDir, "index.html");

    const md = generateReportIndexMarkdown(session, project, findings, verificationMap, detailRunMap, artifactMap, candidateCoverage, agentRuns, outDir);
    const html = generateReportIndexHtml(session, project, findings, verificationMap, detailRunMap, artifactMap);

    writeFileSync(mdPath,   md,   "utf8");
    writeFileSync(htmlPath, html, "utf8");

    return JSON.stringify({
      markdown: mdPath,
      html:     htmlPath,
      findings: findings.length,
      confirmed_findings: findings.filter((finding) => detailRunMap[finding.id]?.status === "COMPLETED").length,
      rejected_findings: findings.filter((finding) => detailRunMap[finding.id]?.status === "REJECTED").length,
      finding_reports: Object.values(artifactMap).map((artifact) => artifact.markdown_path),
      agent_runs: agentRuns.length,
      candidate_coverage: candidateCoverage.length,
      unchecked_candidates: candidateCoverage.reduce((sum, row) => sum + Number(row.unchecked ?? 0), 0),
      critical: findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === "Critical").length,
      high:     findings.filter(f => effectiveSeverity(f, verificationMap[f.id]) === "High").length,
    });
  },
});

// ─── Plugin export ────────────────────────────────────────────────────────────

export default async (_ctx) => ({
  tool: {
    audit_init_session:    auditInitSession,
    audit_start_agent_run: auditStartAgentRun,
    audit_checkpoint_agent_run: auditCheckpointAgentRun,
    audit_get_agent_resume_context: auditGetAgentResumeContext,
    audit_resume_agent_run: auditResumeAgentRun,
    audit_finish_agent_run: auditFinishAgentRun,
    audit_list_agent_runs: auditListAgentRuns,
    audit_save_finding:    auditSaveFinding,
    audit_save_sink_chain: auditSaveSinkChain,
    audit_save_sink_candidates: auditSaveSinkCandidates,
    audit_get_unchecked_sinks: auditGetUncheckedSinks,
    audit_get_sink_coverage: auditGetSinkCoverage,
    audit_save_candidates: auditSaveCandidates,
    audit_upsert_candidates: auditSaveCandidates,
    audit_get_unchecked_candidates: auditGetUncheckedCandidates,
    audit_get_candidate_coverage: auditGetCandidateCoverage,
    audit_save_verification: auditSaveVerification,
    audit_update_finding_after_verification: auditUpdateFindingAfterVerification,
    audit_get_findings_for_verification: auditGetFindingsForVerification,
    audit_list_findings_for_detail: auditListFindingsForDetail,
    audit_start_finding_detail_run: auditStartFindingDetailRun,
    audit_checkpoint_finding_detail_run: auditCheckpointFindingDetailRun,
    audit_get_finding_detail_context: auditGetFindingDetailContext,
    audit_save_finding_report_details: auditSaveFindingReportDetails,
    audit_generate_finding_report: auditGenerateFindingReport,
    audit_finish_finding_detail_run: auditFinishFindingDetailRun,
    audit_save_attack_chain: auditSaveAttackChain,
    audit_complete_session: auditCompleteSession,
    audit_list_sessions:   auditListSessions,
    audit_generate_report: auditGenerateReport,
    audit_generate_report_index: auditGenerateReport,
  },
});
