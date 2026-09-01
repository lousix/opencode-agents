# Feature Incremental Security Review Supplement Template

Use this template for the feature-scoped supplement of Git incremental deep reviews. The canonical final report should be generated through `audit_generate_report` when available.

```markdown
# Feature Security Review: <feature name>

## Scope

| Field | Value |
|------|-------|
| Repository | `<repo_root>` |
| Feature | `<feature name>` |
| Git target | `<mode/base/head/commits/patch>` |
| Engine | `autonomous | agents | hybrid` |
| Graph context | `none | low | medium | high` |
| Canonical report | `<report_dir>/index.md` and `<report_dir>/index.html` |
| Finding reports | `<report_dir>/details/<id>-<component>-<Chinese-title>.md` |
| Process record | `<work_dir>/feature_review.md` |
| Work artifacts | `<work_dir>` |

### Code Scope

- Changed files reviewed:
- Supporting files reviewed:
- Graph-derived supporting files:
- Graph review queue consumed:
- Excluded files:
- Deferred items:

### Document Context

- Provided docs:
- Inferred context:
- Doc/code conflicts:
- Missing context:

## Feature Profile

Describe the feature intent, actors, assets, entrypoints, trust boundaries, and expected security properties.

## Reviewed Feature Surfaces

| Surface | Security Property | Evidence | Outcome |
|---------|-------------------|----------|---------|
| `<entrypoint/control/sink>` | `<authz/validation/signature/...>` | `<files:lines>` | `Reported / No issue found / Rejected / Needs follow-up` |

## Graph Context

| Provider | Status | Contribution | Limitations |
|----------|--------|--------------|-------------|
| `codegraph` | `<ok/missing/not_indexed/error>` | `<callers/callees/impact/routes>` | `<stale/mismatch/none>` |
| `code-review-graph` | `<ok/missing/not_indexed/error>` | `<risk/flows/test gaps>` | `<stale/mismatch/none>` |

Graph context was used as the first navigation input when `graph_review_queue` was non-empty. It is not vulnerability evidence; every cited graph-derived file was read as source before being used in analysis.

Top graph queue items reviewed:

| Priority | Kind | Symbol | File | Disposition |
|----------|------|--------|------|-------------|

## Candidate Coverage And Known Gaps

| Kind | Dimension | Candidates | Triaged | Unchecked | Notes |
|------|-----------|------------|---------|-----------|-------|

List every OPEN/TIMEOUT/deferred item with exact file, line or hunk, reason, and next step.

## Findings

If no finding survives, include:

```text
No reportable findings survived feature binding, changed-code binding, and validation gates.
```

For each finding:

### [<severity-id>] <title>

| Field | Value |
|------|-------|
| Severity | `Critical | High | Medium | Low` |
| Confidence | `已验证 | 高置信 | 中置信 | 需验证` |
| CWE | `<CWE>` |
| Feature binding | `<why this belongs to the feature>` |
| Changed-code binding | `<changed file:hunk or changed control>` |
| Affected lines | `<path:line>` |
| Verification | `<TRUE_SOURCE / PARTIAL / SINK_ONLY / FALSE_POSITIVE>` |

#### Summary

Explain the security issue from the feature perspective.

#### Expected Security Property

State the property from docs or code-inferred behavior, such as tenant isolation, admin-only access, callback signature verification, path confinement, or SQL parameterization.

#### Root Cause

Explain the broken control and the changed code that introduced, weakened, or exposed it.

#### Dataflow / Control Flow

```text
Source/entrypoint -> transform/control -> sink/effect
```

Include file:line evidence for source/control/sink.

#### Reachability

Explain attacker role, entrypoint, preconditions, and exploit result.

#### Severity

Explain the final severity and what evidence could raise or lower it.

#### PoC / Verification Steps

Provide safe, minimal reproduction steps or payload shape.

#### Remediation

Give 1-3 concrete fix directions and test ideas.

## Positive Security Notes

List relevant controls that were present and effective.

## Unresolved Evidence Gaps

Record concrete unresolved feature-specific evidence gaps, the conservative assumption used, and confidence impact. Do not ask the user to respond and do not block the report.
```

## Report Gates

Before writing final findings:

- every final finding must bind to the feature and to changed code or changed control
- Critical/High must have TRUE_SOURCE or a clearly justified high-confidence broken control
- findings unrelated to the feature become `Reviewed Feature Surfaces`, not final findings
- every `deep_review_input.csv` row must have a `work_ledger.md` receipt
- candidate coverage must be summarized from DB or agent `CANDIDATE_LEDGER`
