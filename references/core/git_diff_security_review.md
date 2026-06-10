# Feature-Centric Git Incremental Security Review

> This method reviews a feature implemented across commits, PRs, branches, or patches. The unit of security reasoning is the feature, not the hunk.

## Why Feature-Centric

Real changes often arrive as a group:

- multiple developers
- multiple commits
- multiple PRs
- supporting docs, tests, migrations, and config changes

A vulnerable feature may look safe in each isolated hunk but fail when the whole behavior is assembled. Review the new capability, its trust boundaries, and its expected security properties.

## Deep-Only Policy

Incremental review is always deep. The scope is already bounded by feature and Git range, so the review should spend effort on:

- feature intent and abuse cases
- changed entrypoints
- changed authorization and ownership checks
- changed validation, canonicalization, signing, replay, and tenant isolation
- changed sinks and shared helpers
- old sinks made newly reachable by changed controls
- dependency/config/CI changes that alter runtime security

## Execution Engines

### Autonomous

Default. The auditor explores freely:

```text
feature -> abuse cases -> changed code -> supporting context -> proof -> report
```

Use D1-D10 only after exploration to check coverage and classify findings.

### Agents

Use when the user requests structured parallel review or the feature is large. Dispatch existing D1-D10 agents with the feature and diff contract.

### Hybrid

Use autonomous exploration first, then call agents for high-risk clusters such as dynamic SQL, authz refactors, deserialization, file/network sinks, or dependency/config changes.

## Optional Graph Context

When available, use local graph tools to enrich the review before vulnerability discovery:

- CodeGraph can provide symbol search, callers, callees, impact radius, and route-aware context.
- code-review-graph can provide risk-scored changed functions, affected flows, review priorities, and test gaps.

Graph context answers "where should I look next?" It does not answer "is this exploitable?"

Graph context must be used as a navigation input, not as report decoration. If the adapter produces `graph_review_queue`, that queue becomes the first reading order for vulnerability discovery:

```text
changed_symbol / review_priority
  -> caller_entrypoint reachability
  -> callee_or_sink behavior
  -> impact radius
  -> ordinary changed-file coverage gaps
```

For example, if a changed route reaches a shared outbound HTTP helper, review the route and helper before unrelated changed files. If the helper has many callers, use reverse callers to estimate blast radius and find other feature entrypoints.

The harness should:

1. run `references/core/graph_context_adapter.py` after deterministic Git worklist generation
2. read `graph_review_queue` and process it before plain diff-file order
3. merge graph-derived files into `[RELEVANT_SUPPORTING_FILES]` with explicit reasons
4. prefer graph files when checking feature entrypoints, callers, old sinks made reachable, and test gaps
5. continue normally if no graph provider is available
6. record stale, missing, empty, or base-mismatched graph indexes as limitations

## Feature Security Questions

Ask these before pattern matching:

1. What capability did the feature add or change?
2. Who can trigger it?
3. What data or control plane does it touch?
4. What old code paths did it make newly reachable?
5. What security property does the feature rely on?
6. Where is that property enforced in code?
7. Did the diff weaken, bypass, relocate, or duplicate the enforcement?
8. What docs or PR text claim should be verified against code?

## Changed-Code Binding

A final finding must satisfy at least one:

- vulnerable line is newly added or modified
- guard/control line is newly added, removed, moved, weakened, or made inconsistent
- changed entrypoint reaches an old vulnerable sink
- changed config/profile/dependency makes an old path newly exposed
- changed shared helper affects changed call sites or feature behavior

Do not report unrelated historical bugs as final findings. Put them in follow-up only if they are interesting but not feature-bound.

## Supporting Context Rules

Supporting files may be read when needed to prove behavior:

| Reason | Examples |
|--------|----------|
| `caller` | route/controller/job calling changed helper |
| `callee` | shared sink or validator called by changed code |
| `auth_chain` | filter, middleware, guard, permission annotation |
| `route_registry` | router, controller mapping, OpenAPI |
| `sanitizer` | validation, canonicalization, parameterization |
| `sink_helper` | SQL builder, file helper, HTTP client wrapper |
| `config_profile` | app profiles, feature flags, deployment config |
| `dependency_context` | package manifests, lockfiles, SBOM, CI |

Every supporting file must have a reason in `[RELEVANT_SUPPORTING_FILES]`.

## Candidate Classification

Use the existing candidate state machine:

```text
TRACED_VULN
TRACED_SAFE
TRACED_SANITIZED
TRACED_NO_SOURCE
FALSE_POSITIVE
EXCLUDED_TEST
EXCLUDED_VENDOR
UNREACHABLE
OPEN
TIMEOUT
```

Additional incremental evidence fields should appear in `reason` or `evidence`:

```text
feature_binding
changed_code_binding
supporting_files
doc_claim
counterevidence
```

## No-Findings Standard

No findings is acceptable only when the report explains:

- reviewed feature surfaces
- expected security properties checked
- worklist coverage status
- candidate coverage status
- open gaps, if any
