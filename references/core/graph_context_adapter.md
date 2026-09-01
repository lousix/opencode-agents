# Graph Context Adapter

This adapter optionally enriches feature-centric incremental security review with local code graph tools.

## Goals

- Detect whether `codegraph` or `code-review-graph` is already available.
- Read existing graph indexes only; do not install tools or build large indexes unless the user explicitly requests it.
- Produce a compact, deterministic context artifact for the audit harness.
- Produce a graph-first review queue that changes the audit reading order before ordinary diff-file review.
- Preserve zero-config fallback when graph tools are missing.

## Pre-Audit Initialization

Graph indexes are stored in the **target repository**, not in the audit framework repository:

```text
<target_repo>/
  .codegraph/
  .code-review-graph/
  .audit-work/
  audit-reports/
```

Before a Git incremental audit, run the preparation script from this audit framework:

```bash
python3 references/core/init_graph_context.py --repo <target_repo> --mode update
```

Modes:

| mode | Behavior |
|------|----------|
| `status` | Inspect provider status only; does not build/update indexes or write exclude entries. |
| `init` | Build missing indexes; leave existing indexes untouched. |
| `update` | Build missing indexes or incrementally update existing indexes. Default. |

The script writes these entries to the target repository's local `.git/info/exclude` during `init` / `update`:

```text
.codegraph/
.code-review-graph/
.audit-work/
audit-reports/
```

It never edits the tracked `.gitignore` file. Use `--skip-exclude` when a caller wants to manage ignores separately.

Useful commands:

```bash
python3 references/core/init_graph_context.py --repo <target_repo> --mode status
python3 references/core/init_graph_context.py --repo <target_repo> --mode update --providers codegraph
python3 references/core/init_graph_context.py --repo <target_repo> --mode update --json
```

Run this script after checking out/applying the code state to be audited, so graph context can see changed symbols, routes, callers/callees, and test gaps.

## Provider Semantics

### CodeGraph

Useful for symbol-level navigation:

- `codegraph status --json`
- `codegraph query <symbol> --json`
- `codegraph callers <symbol> --json`
- `codegraph callees <symbol> --json`
- `codegraph impact <symbol> --json`

Best use in our harness:

- changed symbol discovery from changed file stems
- caller/callee supporting files
- impact-radius supporting files
- high-risk callee reverse-caller expansion for shared helpers such as HTTP clients, file helpers, cache clearers, auth helpers, and query builders

CodeGraph results also need selection quality controls. Query results and caller/callee/impact lists can be large and provider order is not a security priority order. The adapter therefore:

1. queries a bounded number of graph roots
2. over-fetches a small amount per query, then selects roots by category, component, and security score
3. filters ordinary tests and build/generated/vendor artifacts out of the primary compact context
4. keeps a capped amount of high-signal test/integration harness context
5. selects supporting files and navigation edges by the same category/component policy instead of alphabetic path order
6. records raw/selected root and edge counts in `providers[].selection`

Unlike `code-review-graph`, CodeGraph is queried interactively and may return thousands of edge items across roots; the adapter does not persist a full raw CodeGraph dump by default. Re-run CodeGraph CLI queries from `navigation_edges` or `graph_review_queue` when deeper expansion is needed.

### code-review-graph

Useful for PR/delta review context:

- `code-review-graph detect-changes --repo <repo> --base <base>`

Best use in our harness:

- risk score
- changed functions/classes
- affected flows
- test gaps
- review priorities

`detect-changes --base <base>` is base-sensitive. If `<base>` is the current `HEAD`, or if `git diff <base> HEAD` has no tracked source changes, the provider may correctly return zero changed functions even when its `.code-review-graph` database has nodes and edges. For a 10-commit review, use the parent/base before those commits, for example `HEAD~10` or the merge base with the target branch.

The adapter must not preserve the raw `detect-changes` path order when truncating large result sets. `detect-changes` can return hundreds of changed functions sorted by path, so a simple prefix slice can hide later components. The adapter therefore applies component-stratified, risk-sorted selection:

1. group changed functions and test gaps by target component
2. exclude build/generated/vendor artifacts from the primary queue
3. prioritize production code and security-relevant build/config surfaces
4. allow only a small capped budget for high-signal test or integration harnesses
5. exclude ordinary unit tests and test gaps in test files from the primary queue
6. keep a minimum representative set from each component
7. fill remaining slots by `risk_score` and security keyword relevance
8. record raw/selected counts, component distributions, category counts, excluded counts, and test ratios in provider selection metadata

The full raw `detect-changes` output is still written next to `graph_context.json` as `code_review_graph_raw.json`; selection only controls the compact navigation context.

This selection policy is a context budget rule only. It must not be interpreted as a vulnerability verdict.

## Graph-First Review Queue

`graph_context.json` includes:

```text
graph_first_required: true|false
graph_review_queue:
  priority
  kind
  symbol
  file
  line
  reasons
  providers
  review_action
navigation_edges:
  edge
  from
  to
  file
  line
  reason
providers[].selection:
  raw_changed_symbols_count
  selected_changed_symbols_count
  raw_edge_items_count
  selected_edge_items_count
  raw_components
  selected_components
  raw_categories
  selected_categories
  excluded_test_count
  excluded_build_artifact_count
  raw_test_symbol_ratio
  selected_test_symbol_ratio
  selection_policy
raw_artifacts:
  code_review_graph_raw.json
```

Queue semantics:

| kind | Meaning | Required action |
|------|---------|-----------------|
| `review_priority` | Provider risk-ranked changed function/class | Read before ordinary changed-file order. |
| `changed_symbol` | Symbol matched from changed files or provider priorities | Use as caller/callee tracing root. |
| `caller_entrypoint` | Caller of changed code or high-risk helper | Check user reachability and trust boundary. |
| `callee_or_sink` | Callee reached from changed code | Check sink/helper behavior and shared blast radius. |
| `affected_flow_file` | File in provider affected flow | Read while validating the feature execution path. |
| `impact_file` | File in CodeGraph impact radius | Read if the feature path remains plausible. |
| `test_gap` | Changed code with weak/missing tests | Use as validation/counterevidence signal, not vulnerability proof. |

The queue must be consumed before plain `deep_review_input.csv` order. The normal worklist is still required afterward to cover files not represented by graph tools, especially non-Docker config, CI, generated patch-only files, docs, and non-code resources. Dockerfile、Compose 与 Docker 目录始终排除。

## Confidence Levels

| confidence | Meaning |
|------------|---------|
| `none` | no provider available or no graph data |
| `low` | provider detected but only partial path/symbol data available |
| `medium` | provider returned changed symbols or impacted files |
| `high` | provider returned impacted files plus affected flows or caller/callee data |

## Security Rules

- Graph output is context, not proof.
- All final finding evidence must come from actual source reads and validation.
- Stale or mismatched graph indexes must be recorded as limitations.
- If graph context conflicts with code evidence, code evidence wins.

## Artifacts

```text
<work_dir>/06_graph_context/
  graph_context.json
  graph_context.md
```

`graph_context.json` is machine-readable and can feed `[RELEVANT_SUPPORTING_FILES]`.
`graph_context.md` is the human-readable audit trail.

When `graph_review_queue` is non-empty, it should feed `[GRAPH_REVIEW_QUEUE]` and drive the first vulnerability-discovery pass. Treat using it only as report material as an incomplete audit process.
