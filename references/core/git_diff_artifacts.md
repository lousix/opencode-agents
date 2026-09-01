# Git Diff Security Review Artifacts

> 功能增量深度审计的落盘协议。路径以被审计项目为锚点，便于把报告随目标项目一起交付。

## Base Paths

```text
repo_root=<target project absolute path>
repo_name=<basename of repo_root>
scan_id=<feature_slug>_<timestamp>_<scope_hash>
report_dir=<repo_root>/audit-reports
work_dir=<repo_root>/.audit-work/git-diff/<scan_id>
```

## Directory Layout

```text
<report_dir>/
  index.md                       # Chinese merged full report with all confirmed finding bodies
  index.html                     # lightweight browser view of the index
  details/<id>-<component>-<Chinese-title>.md # canonical per-finding reports; no per-finding HTML

<work_dir>/
  feature_review.md              # internal feature-scoped process record; not a formal deliverable
  01_context/
    feature_profile.md
    feature_docs.md
    threat_model.md
    diff_scope.md
  02_worklist/
    diff_worklist.csv
    deep_review_input.csv
    work_ledger.md
  03_candidates/
    candidate_summary.md
    reviewed_feature_surfaces.md
  04_validation/
    validation_summary.md
    attack_path_notes.md
  05_agent_outputs/
    autonomous_notes.md
    agent_dispatch_plan.md
  06_graph_context/
    graph_context.json
    graph_context.md
    code_review_graph_raw.json
```

`report_dir` 的结构、文件名、语言和内容门禁必须与 `code-audit` 相同。`work_dir` 只保存增量审计过程证据、覆盖台账和中断重续状态，不能作为另一套对外交付报告。

## Context Artifacts

### `feature_profile.md`

Records the functional boundary:

```text
feature name
intent
actors
assets
entrypoints
trust boundaries
expected security properties
context gaps
```

### `feature_docs.md`

Summarizes optional docs, PR descriptions, issue text, API specs, test plans, and conflicts with code evidence.

Rules:
- docs help infer expected behavior
- docs cannot prove a vulnerability by themselves
- code evidence wins for exploitability

### `threat_model.md`

Feature-scoped threat model. It should still mention repository-level context from `audit-context.md` when available, but must focus on what the feature changes.

### `diff_scope.md`

Human-readable summary of Git target resolution:

```text
mode
base/head
commit list
patch files
changed files
renames/deletes
excluded paths
scope limitations
```

## Worklist Artifacts

### `diff_worklist.csv`

Deterministic CSV from `references/core/git_diff_worklist.py`.

Columns:

```text
path,status,area,is_source_like,is_security_relevant,old_path,hunks,preview,exclude_reason
```

### `deep_review_input.csv`

Rows that must receive deep review.

Columns:

```text
path,area,reason,hunks
```

Every source-like or security-relevant changed file should appear unless explicitly suppressed with a reason.

### `work_ledger.md`

File-level completion receipts. Each row should include:

```text
file
hunks
feature behavior
security properties checked
supporting files read
candidate ids
disposition
reason
```

Coverage is not complete until every `deep_review_input.csv` row has one of:

```text
covered | not_applicable | suppressed | deferred
```

## Candidate Artifacts

Candidate details should be saved through the existing audit DB:

```text
audit_upsert_candidates(agent_run_id=...)
audit_save_finding(...)
audit_save_sink_chain(...)
audit_save_verification(...)
```

`candidate_summary.md` is only a readable summary of DB-backed candidate coverage:

```text
candidate_kind
dimension
candidates
triaged
unchecked
high_path
OPEN/TIMEOUT list
```

Do not write separate JSONL candidate ledgers.

## Validation Artifacts

### `validation_summary.md`

Records final validation decisions:

```text
candidate id
feature binding
changed line/control binding
source/control/sink evidence
counterevidence
verdict
severity action
```

### `attack_path_notes.md`

Required for Critical/High findings and optional for Medium/Low. It should explain the concrete attacker path through the feature.

## Graph Context Artifacts

### `graph_context.json`

Optional machine-readable output from `references/core/graph_context_adapter.py`.

It records:

```text
provider status
graph confidence
risk score
changed symbols
graph-first review queue
navigation edges
affected flows
test gaps
graph-derived supporting files
limitations
```

### `graph_context.md`

Human-readable summary of provider status and graph-derived supporting files.

### `code_review_graph_raw.json`

Optional full raw `code-review-graph detect-changes` output. The adapter may exclude ordinary tests, build artifacts, generated files, or low-priority items from compact navigation context, but the raw provider output should remain available here for auditability.

Rules:
- graph context is optional and must not block the audit when unavailable
- graph output is context, not vulnerability evidence
- if `graph_review_queue` is non-empty, it drives the first vulnerability-discovery reading order
- every graph-derived supporting file must still be read before it can support a finding
- stale, missing, or mismatched graph indexes must be recorded as limitations

## Final Report

The canonical finding reports must come from the DB-backed per-finding report pipeline:

```text
audit_list_findings_for_detail(session_id, include_terminal=false)
dispatch one audit-verification agent per finding_id
audit_generate_report_index(session_id, output_dir=<report_dir>, allow_unverified=false)
```

Each confirmed finding produces Chinese Markdown only. `index.md` merges the complete current body of every confirmed finding, while `index.html` remains a lightweight management index. The merged content must come from current per-finding artifacts rather than a second free-form rewrite, preserving per-finding verification, resumable checkpoints, sink-chain validation, severity calibration, remediation facts, and the audit DB contract.

`feature_review.md` is an internal Git incremental process record under `<work_dir>`. It must include feature scope, diff scope, worklist/graph coverage, changed-code binding notes, reviewed surfaces, and known gaps, but it must not be listed as a formal report deliverable.

Do not create `report.md`, per-finding HTML, or any Git Diff-specific formal report directory. If the report pipeline is unavailable, the feature template remains a limited process record and must not be presented as a completed per-finding report; record that limitation explicitly.
