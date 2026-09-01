#!/usr/bin/env python3
"""Optional graph-context enrichment for feature incremental security review.

The adapter is deliberately conservative:
- it never installs tools
- it never builds indexes automatically
- it treats graph output as context, not vulnerability evidence
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = int(os.environ.get("AUDIT_GRAPH_CONTEXT_TIMEOUT", "20"))
MAX_PROVIDER_FILES = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_FILES", "80"))
MAX_SYMBOLS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_SYMBOLS", "24"))
MAX_SECONDARY_SYMBOLS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_SECONDARY_SYMBOLS", "8"))
MAX_REVIEW_QUEUE = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_REVIEW_QUEUE", "60"))
MAX_CONTEXT_CHANGED_SYMBOLS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CHANGED_SYMBOLS", "200"))
MAX_NAVIGATION_EDGES = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_NAVIGATION_EDGES", "200"))
MAX_CG_CHANGED_SYMBOLS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CG_CHANGED_SYMBOLS", "40"))
MAX_CG_MATCHES_PER_QUERY = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CG_MATCHES_PER_QUERY", "4"))
MAX_CG_EDGE_ITEMS_PER_GROUP = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CG_EDGE_ITEMS_PER_GROUP", "20"))
MAX_CRG_CHANGED_SYMBOLS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CRG_CHANGED_SYMBOLS", "120"))
MAX_CRG_TEST_GAPS = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CRG_TEST_GAPS", "120"))
MAX_CRG_REVIEW_PRIORITIES = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CRG_REVIEW_PRIORITIES", "40"))
MIN_CRG_ITEMS_PER_COMPONENT = int(os.environ.get("AUDIT_GRAPH_CONTEXT_MIN_CRG_ITEMS_PER_COMPONENT", "3"))
MAX_CRG_TEST_AUX_RATIO = float(os.environ.get("AUDIT_GRAPH_CONTEXT_MAX_CRG_TEST_AUX_RATIO", "0.15"))

BUILD_ARTIFACT_DIRS = {
    ".cache",
    ".gradle",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "bin",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "third_party",
    "third-party",
    "vendor",
}

GENERATED_SUFFIXES = (
    ".generated.go",
    ".pb.go",
    ".pb.cc",
    ".pb.h",
    ".min.js",
)

SECURITY_CONFIG_FILENAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "go.mod",
    "go.sum",
    "makefile",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pom.xml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
    "yarn.lock",
}

SECURITY_CONFIG_PREFIXES = (
    ".github/workflows/",
    ".gitlab-ci",
    "charts/",
    "ci/",
    "deploy/",
    "docker/",
    "helm/",
    "k8s/",
    "kubernetes/",
    "terraform/",
)

TEST_AUX_PATH_HINTS = (
    "/e2e/",
    "/integration/",
    "/presmoke/",
    "/security/",
    "/st/",
    "/system/",
)

SECURITY_KEYWORDS = {
    "auth",
    "authorize",
    "admin",
    "cache",
    "chat",
    "clear",
    "command",
    "connect",
    "cookie",
    "credential",
    "crypt",
    "delete",
    "decrypt",
    "download",
    "embed",
    "encrypt",
    "eval",
    "exec",
    "file",
    "hash",
    "http",
    "key",
    "login",
    "llm",
    "load",
    "open",
    "path",
    "password",
    "permission",
    "pickle",
    "post",
    "privilege",
    "prompt",
    "query",
    "redirect",
    "request",
    "retrieval",
    "rerank",
    "secret",
    "session",
    "sign",
    "shell",
    "socket",
    "sql",
    "ssrf",
    "subprocess",
    "token",
    "upload",
    "url",
    "validate",
    "verify",
    "yaml",
}

ENTRYPOINT_KEYWORDS = {
    "api",
    "controller",
    "endpoint",
    "handler",
    "route",
    "view",
    "post ",
    "get ",
    "put ",
    "delete ",
    "patch ",
}


def run_cmd(args: list[str], cwd: Path, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def read_worklist(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not path.exists():
        return rows
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            p = (row.get("path") or "").strip()
            if p:
                rows.append({k: v or "" for k, v in row.items()})
    return rows


def normalize_repo_path(repo: Path, value: str) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    # Remove line suffixes if a provider returns path:line.
    value = re.sub(r":\d+(?::\d+)?$", "", value)
    path = Path(value)
    try:
        if path.is_absolute():
            rel = path.resolve().relative_to(repo.resolve())
            return rel.as_posix()
        return path.as_posix()
    except ValueError:
        return None


def add_supporting_file(
    files: dict[str, dict[str, Any]],
    repo: Path,
    path_value: str | None,
    reason: str,
    provider: str,
    detail: str = "",
) -> None:
    rel = normalize_repo_path(repo, path_value or "")
    if not rel:
        return
    lowered = rel.lower()
    if lowered.startswith((".git/", ".audit-work/", "audit-reports/")):
        return
    parts = Path(lowered).parts
    name = Path(lowered).name
    docker_compose = name.endswith((".yml", ".yaml")) and (
        name.startswith("docker-compose.") or name.startswith("compose.")
    )
    if "docker" in parts or ".docker" in parts or name == "dockerfile" or name.startswith("dockerfile.") or docker_compose:
        return
    entry = files.setdefault(
        rel,
        {"path": rel, "reasons": [], "providers": [], "details": []},
    )
    if reason not in entry["reasons"]:
        entry["reasons"].append(reason)
    if provider not in entry["providers"]:
        entry["providers"].append(provider)
    if detail and detail not in entry["details"]:
        entry["details"].append(detail)


def collect_file_values(obj: Any) -> list[str]:
    values: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in {"file", "file_path", "filepath", "path"} and isinstance(value, str):
                values.append(value)
            else:
                values.extend(collect_file_values(value))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(collect_file_values(item))
    return values


def node_name(item: Any, fallback: str = "") -> str:
    if not isinstance(item, dict):
        return fallback
    for key in ("name", "qualifiedName", "qualified_name", "symbol", "label"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return fallback


def node_file(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("filePath", "file_path", "file", "path", "filepath"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def node_line(item: Any) -> int | None:
    if not isinstance(item, dict):
        return None
    for key in ("line", "lineStart", "line_start", "startLine", "start_line"):
        value = item.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def risk_value(item: Any) -> float:
    if not isinstance(item, dict):
        return 0.0
    value = item.get("risk_score") or item.get("riskScore") or 0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def item_component(repo: Path, item: Any) -> str:
    rel = normalize_repo_path(repo, node_file(item) or "")
    if not rel:
        return "unknown"
    parts = Path(rel).parts
    if not parts:
        return "unknown"
    if parts[0] in {"test", "tests"} and len(parts) > 1:
        if "." in parts[1]:
            return parts[0]
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def is_test_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if bool(item.get("is_test")):
        return True
    name = node_name(item).lower()
    file_value = node_file(item).lower()
    filename = Path(file_value).name.lower()
    return (
        "/test/" in file_value
        or "/tests/" in file_value
        or filename.startswith("test_")
        or filename.endswith("_test.py")
        or filename.endswith("_test.go")
        or filename.endswith("test.java")
        or name.startswith("test")
        or "testcase" in name
    )


def item_rel_path(repo: Path, item: Any) -> str:
    return normalize_repo_path(repo, node_file(item) or "") or ""


def is_build_artifact_path(rel: str) -> bool:
    if not rel:
        return False
    lowered = rel.lower()
    parts = set(Path(lowered).parts)
    if parts & BUILD_ARTIFACT_DIRS:
        return True
    return lowered.endswith(GENERATED_SUFFIXES)


def is_security_config_path(rel: str) -> bool:
    lowered = rel.lower()
    name = Path(lowered).name
    return name in SECURITY_CONFIG_FILENAMES or lowered.startswith(SECURITY_CONFIG_PREFIXES)


def is_test_auxiliary_item(repo: Path, item: Any) -> bool:
    rel = "/" + item_rel_path(repo, item).lower()
    symbol = node_name(item).lower()
    if not is_test_item(item):
        return False
    if any(hint in rel for hint in TEST_AUX_PATH_HINTS):
        return True
    return keyword_score(symbol, rel) >= 16


def item_selection_category(repo: Path, item: Any) -> str:
    rel = item_rel_path(repo, item)
    if is_build_artifact_path(rel):
        return "build_artifact"
    if is_security_config_path(rel):
        return "config_supply_chain"
    if is_test_auxiliary_item(repo, item):
        return "test_auxiliary"
    if is_test_item(item):
        return "test_noisy"
    return "production"


def annotate_selection(repo: Path, item: dict[str, Any]) -> dict[str, Any]:
    annotated = dict(item)
    category = item_selection_category(repo, item)
    annotated["selection_category"] = category
    if category == "production":
        annotated["selection_reason"] = "production code"
    elif category == "config_supply_chain":
        annotated["selection_reason"] = "security-relevant build/config surface"
    elif category == "test_auxiliary":
        annotated["selection_reason"] = "high-signal test or integration harness"
    elif category == "test_noisy":
        annotated["selection_reason"] = "ordinary test code excluded from primary queue"
    else:
        annotated["selection_reason"] = "build/generated/vendor artifact excluded from primary queue"
    return annotated


def component_counts(repo: Path, items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        component = item_component(repo, item)
        counts[component] = counts.get(component, 0) + 1
    return dict(sorted(counts.items()))


def category_counts(repo: Path, items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        category = item.get("selection_category") or item_selection_category(repo, item)
        counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items()))


def select_component_representative_items(
    repo: Path,
    items: list[Any],
    limit: int,
    min_per_component: int = MIN_CRG_ITEMS_PER_COMPONENT,
    include_test_auxiliary: bool = True,
    include_noisy_tests: bool = False,
    include_build_artifacts: bool = False,
) -> list[dict[str, Any]]:
    """Select graph items without letting path order hide later components."""
    normalized = [annotate_selection(repo, item) for item in items if isinstance(item, dict)]
    allowed_categories = {"production", "config_supply_chain"}
    if include_test_auxiliary:
        allowed_categories.add("test_auxiliary")
    if include_noisy_tests:
        allowed_categories.add("test_noisy")
    if include_build_artifacts:
        allowed_categories.add("build_artifact")
    filtered = [
        item for item in normalized
        if item.get("selection_category") in allowed_categories
    ]
    if include_test_auxiliary and not include_noisy_tests:
        test_aux_limit = max(1, int(limit * MAX_CRG_TEST_AUX_RATIO))
        selected_test_aux = 0
        capped: list[dict[str, Any]] = []
        for item in sorted(
            filtered,
            key=lambda value: (
                value.get("selection_category") == "test_auxiliary",
                -risk_value(value),
                -keyword_score(node_name(value), node_file(value)),
                node_file(value),
                node_name(value),
            ),
        ):
            if item.get("selection_category") == "test_auxiliary":
                if selected_test_aux >= test_aux_limit:
                    continue
                selected_test_aux += 1
            capped.append(item)
        filtered = capped
    normalized = filtered
    if len(normalized) <= limit:
        def direct_sort_key(item: dict[str, Any]) -> tuple[float, int, int, str, str]:
            symbol = node_name(item)
            path_value = node_file(item)
            return (
                -risk_value(item),
                1 if item.get("selection_category") == "test_auxiliary" else 0,
                -keyword_score(symbol, path_value),
                path_value,
                symbol,
            )

        return sorted(normalized, key=direct_sort_key)

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in normalized:
        groups.setdefault(item_component(repo, item), []).append(item)

    def sort_key(item: dict[str, Any]) -> tuple[float, int, int, str, str]:
        symbol = node_name(item)
        path_value = node_file(item)
        return (
            -risk_value(item),
            1 if item.get("selection_category") == "test_auxiliary" else 0,
            -keyword_score(symbol, path_value),
            path_value,
            symbol,
        )

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()

    for component in sorted(groups):
        for item in sorted(groups[component], key=sort_key)[:min_per_component]:
            key = (node_name(item), node_file(item), node_line(item))
            if key in seen:
                continue
            seen.add(key)
            selected.append(item)
            if len(selected) >= limit:
                return sorted(selected, key=sort_key)

    for item in sorted(normalized, key=sort_key):
        key = (node_name(item), node_file(item), node_line(item))
        if key in seen:
            continue
        seen.add(key)
        selected.append(item)
        if len(selected) >= limit:
            break
    return sorted(selected, key=sort_key)


def code_review_graph_selection_summary(
    repo: Path,
    raw_changed: list[Any],
    selected_changed: list[dict[str, Any]],
    raw_gaps: list[Any],
    selected_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_changed_dicts = [item for item in raw_changed if isinstance(item, dict)]
    raw_gap_dicts = [item for item in raw_gaps if isinstance(item, dict)]
    test_count = sum(1 for item in raw_changed_dicts if is_test_item(item))
    selected_test_count = sum(1 for item in selected_changed if is_test_item(item))
    raw_annotated = [annotate_selection(repo, item) for item in raw_changed_dicts]
    return {
        "raw_changed_symbols_count": len(raw_changed_dicts),
        "selected_changed_symbols_count": len(selected_changed),
        "raw_test_gaps_count": len(raw_gap_dicts),
        "selected_test_gaps_count": len(selected_gaps),
        "raw_components": component_counts(repo, raw_changed_dicts),
        "selected_components": component_counts(repo, selected_changed),
        "raw_categories": category_counts(repo, raw_annotated),
        "selected_categories": category_counts(repo, selected_changed),
        "excluded_test_count": sum(1 for item in raw_annotated if item.get("selection_category") == "test_noisy"),
        "excluded_build_artifact_count": sum(1 for item in raw_annotated if item.get("selection_category") == "build_artifact"),
        "raw_test_symbol_ratio": round(test_count / len(raw_changed_dicts), 4) if raw_changed_dicts else 0.0,
        "selected_test_symbol_ratio": round(selected_test_count / len(selected_changed), 4) if selected_changed else 0.0,
        "selection_policy": "production/config first; high-signal tests capped; ordinary tests and build artifacts excluded from primary queue; component-stratified risk ordering",
    }


def codegraph_selection_summary(
    repo: Path,
    raw_symbols: list[dict[str, Any]],
    selected_symbols: list[dict[str, Any]],
    raw_edges: list[dict[str, Any]],
    selected_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_all = [*raw_symbols, *raw_edges]
    selected_all = [*selected_symbols, *selected_edges]
    raw_annotated = [annotate_selection(repo, item) for item in raw_all]
    selected_annotated = [annotate_selection(repo, item) for item in selected_all]
    raw_test_count = sum(1 for item in raw_annotated if is_test_item(item))
    selected_test_count = sum(1 for item in selected_annotated if is_test_item(item))
    return {
        "raw_changed_symbols_count": len(raw_symbols),
        "selected_changed_symbols_count": len(selected_symbols),
        "raw_edge_items_count": len(raw_edges),
        "selected_edge_items_count": len(selected_edges),
        "raw_components": component_counts(repo, raw_annotated),
        "selected_components": component_counts(repo, selected_annotated),
        "raw_categories": category_counts(repo, raw_annotated),
        "selected_categories": category_counts(repo, selected_annotated),
        "excluded_test_count": sum(1 for item in raw_annotated if item.get("selection_category") == "test_noisy"),
        "excluded_build_artifact_count": sum(1 for item in raw_annotated if item.get("selection_category") == "build_artifact"),
        "raw_test_symbol_ratio": round(raw_test_count / len(raw_annotated), 4) if raw_annotated else 0.0,
        "selected_test_symbol_ratio": round(selected_test_count / len(selected_annotated), 4) if selected_annotated else 0.0,
        "selection_policy": "production/config first; high-signal tests capped; CodeGraph roots and edge items selected by component-stratified security score",
    }


def selection_score_for_supporting(entry: dict[str, Any]) -> float:
    score = 0.0
    reasons = set(entry.get("reasons") or [])
    if "graph_priority" in reasons:
        score += 0.9
    if "graph_callee" in reasons:
        score += 0.85
    if "graph_caller" in reasons:
        score += 0.8
    if "graph_flow" in reasons:
        score += 0.7
    if "graph_impact" in reasons:
        score += 0.45
    if "graph_test_gap" in reasons:
        score += 0.2
    text = " ".join([entry.get("path", ""), *entry.get("details", [])])
    score += keyword_score(text) / 100.0
    return min(score, 2.0)


def select_supporting_files(
    repo: Path,
    supporting: dict[str, dict[str, Any]],
    changed_set: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    for path, entry in supporting.items():
        if path in changed_set:
            continue
        item = {
            "name": " ".join(entry.get("details", [])) or path,
            "file_path": path,
            "risk_score": selection_score_for_supporting(entry),
        }
        item = annotate_selection(repo, item)
        if item.get("selection_category") in {"test_noisy", "build_artifact"}:
            continue
        candidates.append(item)
        annotated_entry = dict(entry)
        annotated_entry["selection_category"] = item.get("selection_category")
        annotated_entry["selection_reason"] = item.get("selection_reason")
        by_path[path] = annotated_entry
    selected = select_component_representative_items(
        repo,
        candidates,
        limit,
        min_per_component=2,
        include_test_auxiliary=True,
        include_noisy_tests=False,
        include_build_artifacts=False,
    )
    return [by_path[item_rel_path(repo, item)] for item in selected if item_rel_path(repo, item) in by_path]


def edge_selection_score(edge: dict[str, Any]) -> float:
    score = 0.0
    kind = str(edge.get("edge") or "")
    if kind == "callee":
        score += 0.9
    elif kind == "caller":
        score += 0.85
    elif kind == "impact":
        score += 0.5
    text = " ".join(str(edge.get(k) or "") for k in ("from", "to", "file", "reason"))
    score += keyword_score(text) / 100.0
    return min(score, 2.0)


def select_navigation_edges(repo: Path, edges: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in edges:
        key = (
            str(edge.get("edge") or ""),
            str(edge.get("from") or ""),
            str(edge.get("to") or ""),
            str(edge.get("file") or ""),
        )
        item = {
            "name": f"{edge.get('from', '')}->{edge.get('to', '')}",
            "file_path": edge.get("file") or "",
            "line_start": edge.get("line"),
            "risk_score": edge_selection_score(edge),
        }
        item = annotate_selection(repo, item)
        if item.get("selection_category") in {"test_noisy", "build_artifact"}:
            continue
        item["_edge_key"] = key
        candidates.append(item)
        annotated_edge = dict(edge)
        annotated_edge["selection_category"] = item.get("selection_category")
        by_key[key] = annotated_edge
    selected = select_component_representative_items(
        repo,
        candidates,
        limit,
        min_per_component=3,
        include_test_auxiliary=True,
        include_noisy_tests=False,
        include_build_artifacts=False,
    )
    result: list[dict[str, Any]] = []
    for item in selected:
        key = item.get("_edge_key")
        if key in by_key:
            result.append(by_key[key])
    return result


def keyword_score(*values: str) -> int:
    text = " ".join(v for v in values if v).lower()
    score = 0
    for keyword in SECURITY_KEYWORDS:
        if keyword in text:
            score += 8
    if any(keyword in text for keyword in ENTRYPOINT_KEYWORDS) or re.search(r"\b(get|post|put|patch|delete)\s+/", text):
        score += 18
    if "/" in text and any(method in text for method in ("post", "get", "put", "patch", "delete")):
        score += 12
    return min(score, 48)


def add_review_queue_item(
    queue: dict[tuple[str, str, str], dict[str, Any]],
    repo: Path,
    *,
    kind: str,
    symbol: str,
    path_value: str | None,
    line: int | None,
    reason: str,
    provider: str,
    score: int,
    review_action: str,
) -> None:
    rel = normalize_repo_path(repo, path_value or "") or ""
    key = (kind, symbol or "", rel)
    entry = queue.setdefault(
        key,
        {
            "kind": kind,
            "symbol": symbol,
            "file": rel,
            "line": line,
            "score": score,
            "reasons": [],
            "providers": [],
            "review_action": review_action,
        },
    )
    entry["score"] = max(entry.get("score", 0), score)
    if line and not entry.get("line"):
        entry["line"] = line
    if reason and reason not in entry["reasons"]:
        entry["reasons"].append(reason)
    if provider not in entry["providers"]:
        entry["providers"].append(provider)


def add_navigation_edge(
    edges: list[dict[str, Any]],
    repo: Path,
    *,
    provider: str,
    edge: str,
    from_symbol: str,
    to_item: Any,
    reason: str,
) -> None:
    to_symbol = node_name(to_item)
    rel = normalize_repo_path(repo, node_file(to_item) or "") or ""
    edges.append(
        {
            "provider": provider,
            "edge": edge,
            "from": from_symbol,
            "to": to_symbol,
            "file": rel,
            "line": node_line(to_item),
            "reason": reason,
        }
    )


def finalize_review_queue(queue: dict[tuple[str, str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    items = sorted(
        queue.values(),
        key=lambda item: (
            -int(item.get("score") or 0),
            item.get("file") or "",
            item.get("symbol") or "",
            item.get("kind") or "",
        ),
    )[:MAX_REVIEW_QUEUE]
    for idx, item in enumerate(items, start=1):
        item["priority"] = idx
    return items


def symbol_queries_from_worklist(rows: list[dict[str, str]], extra_queries: list[str] | None = None) -> list[str]:
    queries: list[str] = []
    seen: set[str] = set()

    context_text = " ".join(
        [row.get("path", "") + " " + row.get("preview", "") for row in rows]
        + [q or "" for q in (extra_queries or [])]
    ).lower()
    risk_seeds: list[str] = []
    if any(term in context_text for term in ("api", "fastapi", "http", "query", "request", "retrieval", "url")):
        risk_seeds.extend(["post", "request", "url"])
    if any(term in context_text for term in ("upload", "download", "file", "path")):
        risk_seeds.extend(["upload", "file", "path"])
    if any(term in context_text for term in ("cache", "clear", "delete")):
        risk_seeds.extend(["cache", "clear", "delete"])
    if any(term in context_text for term in ("auth", "token", "secret", "key")):
        risk_seeds.extend(["auth", "token", "secret"])
    for candidate in risk_seeds:
        if candidate and candidate not in seen:
            seen.add(candidate)
            queries.append(candidate)
            if len(queries) >= MAX_SYMBOLS:
                return queries

    for query in extra_queries or []:
        if not query:
            continue
        seeds: list[str] = []
        if "::" in query:
            seeds.append(query.rsplit("::", 1)[-1])
        elif "/" in query:
            seeds.append(Path(query).stem)
        else:
            seeds.append(query)
        if seeds and "." in seeds[-1]:
            seeds.append(query.rsplit(".", 1)[-1])
        for candidate in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", " ".join(seeds)):
            if candidate and candidate not in seen:
                seen.add(candidate)
                queries.append(candidate)
                if len(queries) >= MAX_SYMBOLS:
                    return queries

    for row in rows:
        path = row.get("path", "")
        stem = Path(path).stem
        candidates = [stem]
        preview = row.get("preview", "")
        candidates.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", preview)[:3])
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            if candidate.lower() in {"index", "main", "test", "utils", "config"}:
                continue
            seen.add(candidate)
            queries.append(candidate)
            if len(queries) >= MAX_SYMBOLS:
                return queries
    return queries


def code_review_graph_provider(repo: Path, rows: list[dict[str, str]], base: str) -> dict[str, Any]:
    provider = {
        "name": "code-review-graph",
        "available": False,
        "status": "missing",
        "notes": [],
        "index_status": "",
        "detected_change_files": None,
        "risk_score": None,
        "changed_symbols": [],
        "affected_flows": [],
        "test_gaps": [],
        "review_priorities": [],
        "selection": {},
    }
    if shutil.which("code-review-graph") is None:
        provider["notes"].append("code-review-graph CLI not found on PATH")
        return provider
    provider["available"] = True
    if not (repo / ".code-review-graph").exists():
        provider["status"] = "not_indexed"
        provider["notes"].append(".code-review-graph index directory not found")
        return provider

    src_files = [row.get("path", "") for row in rows if row.get("path")]
    rc, out, err = run_cmd(["code-review-graph", "status", "--repo", str(repo)], cwd=repo)
    if rc == 0:
        provider["index_status"] = " ".join(out.split())[:500]
    elif err:
        provider["notes"].append(f"status failed: {err.strip()[:200]}")

    rc, diff_out, _ = run_cmd(["git", "diff", "--name-only", base, "HEAD"], cwd=repo)
    tracked_delta_count = len([line for line in diff_out.splitlines() if line.strip()]) if rc == 0 else None

    rc, out, err = run_cmd(
        ["code-review-graph", "detect-changes", "--repo", str(repo), "--base", base],
        cwd=repo,
    )
    if rc != 0:
        provider["status"] = "error"
        provider["notes"].append((err or out).strip()[:500])
        return provider
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        provider["status"] = "error"
        provider["notes"].append("detect-changes did not return JSON")
        return provider

    provider["status"] = "ok"
    provider["risk_score"] = data.get("risk_score")
    provider["_raw_detect_changes"] = data
    raw_changed = data.get("changed_functions", [])
    raw_test_gaps = data.get("test_gaps", [])
    raw_priorities = data.get("review_priorities", [])
    selected_changed = select_component_representative_items(
        repo,
        raw_changed,
        MAX_CRG_CHANGED_SYMBOLS,
        MIN_CRG_ITEMS_PER_COMPONENT,
        include_test_auxiliary=True,
        include_noisy_tests=False,
        include_build_artifacts=False,
    )
    selected_gaps = select_component_representative_items(
        repo,
        raw_test_gaps,
        MAX_CRG_TEST_GAPS,
        MIN_CRG_ITEMS_PER_COMPONENT,
        include_test_auxiliary=False,
        include_noisy_tests=False,
        include_build_artifacts=False,
    )
    selected_priorities = select_component_representative_items(
        repo,
        raw_priorities or raw_changed,
        MAX_CRG_REVIEW_PRIORITIES,
        max(1, min(MIN_CRG_ITEMS_PER_COMPONENT, 2)),
        include_test_auxiliary=True,
        include_noisy_tests=False,
        include_build_artifacts=False,
    )
    provider["changed_symbols"] = selected_changed
    provider["affected_flows"] = data.get("affected_flows", [])[:20]
    provider["test_gaps"] = selected_gaps
    provider["review_priorities"] = selected_priorities
    provider["selection"] = code_review_graph_selection_summary(
        repo,
        raw_changed,
        selected_changed,
        raw_test_gaps,
        selected_gaps,
    )
    summary = data.get("summary") or ""
    match = re.search(r"Analyzed\s+(\d+)\s+changed file", summary)
    if match:
        provider["detected_change_files"] = int(match.group(1))
    if data.get("functions_truncated"):
        provider["notes"].append("changed function analysis was truncated by provider")
    if len(selected_changed) < len([item for item in raw_changed if isinstance(item, dict)]):
        provider["notes"].append(
            "changed functions were component-stratified and risk-sorted before adapter truncation"
        )
    if len(selected_gaps) < len([item for item in raw_test_gaps if isinstance(item, dict)]):
        provider["notes"].append(
            "test gaps were component-stratified before adapter truncation"
        )
    if not provider["changed_symbols"]:
        if tracked_delta_count == 0:
            provider["notes"].append(
                "detect-changes returned no changed functions because git diff base..HEAD has zero tracked files; choose a base before the commits being audited"
            )
        elif src_files:
            provider["notes"].append(
                "detect-changes returned no changed functions; base may point at the indexed/current commit or the delta may contain non-indexed files"
            )
        else:
            provider["notes"].append("detect-changes returned no changed functions and the worklist is empty")
    return provider


def codegraph_provider(repo: Path, rows: list[dict[str, str]], extra_queries: list[str] | None = None) -> dict[str, Any]:
    provider = {
        "name": "codegraph",
        "available": False,
        "status": "missing",
        "notes": [],
        "status_info": {},
        "changed_symbols": [],
        "expanded_symbols": [],
        "callers": [],
        "callees": [],
        "impact": [],
        "selection": {},
    }
    if shutil.which("codegraph") is None:
        provider["notes"].append("codegraph CLI not found on PATH")
        return provider
    provider["available"] = True

    rc, out, err = run_cmd(["codegraph", "status", str(repo), "--json"], cwd=repo)
    if rc != 0:
        provider["status"] = "error"
        provider["notes"].append((err or out).strip()[:500])
        return provider
    try:
        status_info = json.loads(out)
    except json.JSONDecodeError:
        provider["status"] = "error"
        provider["notes"].append("codegraph status did not return JSON")
        return provider
    provider["status_info"] = status_info
    if not status_info.get("initialized"):
        provider["status"] = "not_indexed"
        provider["notes"].append("CodeGraph index is not initialized")
        return provider
    if status_info.get("worktreeMismatch"):
        provider["notes"].append(f"worktree/index mismatch: {status_info.get('worktreeMismatch')}")
    pending = status_info.get("pendingChanges") or {}
    if any((pending.get(k) or 0) for k in ("added", "modified", "removed")):
        provider["notes"].append(f"CodeGraph has pending changes: {pending}")

    provider["status"] = "ok"
    secondary_queries: list[str] = []
    seen_secondary: set[str] = set()
    raw_changed_nodes: list[dict[str, Any]] = []
    selected_changed_nodes: list[dict[str, Any]] = []
    raw_edge_items: list[dict[str, Any]] = []
    selected_edge_items: list[dict[str, Any]] = []
    for query in symbol_queries_from_worklist(rows, extra_queries):
        rc, qout, _ = run_cmd(
            ["codegraph", "query", query, "--path", str(repo), "--limit", str(max(5, MAX_CG_MATCHES_PER_QUERY * 2)), "--json"],
            cwd=repo,
        )
        if rc != 0:
            continue
        try:
            matches = json.loads(qout)
        except json.JSONDecodeError:
            continue
        match_nodes: list[dict[str, Any]] = []
        for match in matches:
            node = match.get("node", match)
            if not isinstance(node, dict):
                continue
            match_nodes.append(node)
        raw_changed_nodes.extend(match_nodes)
        selected_match_nodes = select_component_representative_items(
            repo,
            match_nodes,
            MAX_CG_MATCHES_PER_QUERY,
            min_per_component=1,
            include_test_auxiliary=True,
            include_noisy_tests=False,
            include_build_artifacts=False,
        )
        for node in selected_match_nodes:
            symbol = node.get("name") or node.get("qualifiedName") or query
            provider["changed_symbols"].append(node)
            selected_changed_nodes.append(node)
            for command, key, reason in (
                ("callers", "callers", "graph_caller"),
                ("callees", "callees", "graph_callee"),
                ("impact", "affected", "graph_impact"),
            ):
                rc, rout, _ = run_cmd(
                    ["codegraph", command, str(symbol), "--path", str(repo), "--json"],
                    cwd=repo,
                )
                if rc != 0:
                    continue
                try:
                    result = json.loads(rout)
                except json.JSONDecodeError:
                    continue
                items = [item for item in result.get(key, []) if isinstance(item, dict)]
                raw_edge_items.extend(items)
                selected_items = select_component_representative_items(
                    repo,
                    items,
                    MAX_CG_EDGE_ITEMS_PER_GROUP,
                    min_per_component=2,
                    include_test_auxiliary=True,
                    include_noisy_tests=False,
                    include_build_artifacts=False,
                )
                selected_edge_items.extend(selected_items)
                provider[command if command != "impact" else "impact"].append(
                    {"symbol": symbol, "items": selected_items, "reason": reason}
                )
                if command == "callees":
                    for callee in selected_items[:10]:
                        callee_symbol = node_name(callee)
                        callee_file = node_file(callee)
                        if not callee_symbol or callee_symbol in seen_secondary:
                            continue
                        if keyword_score(callee_symbol, callee_file) < 8:
                            continue
                        seen_secondary.add(callee_symbol)
                        secondary_queries.append(callee_symbol)
                        if len(secondary_queries) >= MAX_SECONDARY_SYMBOLS:
                            break
        if len(provider["changed_symbols"]) >= MAX_CG_CHANGED_SYMBOLS:
            break

    for symbol in secondary_queries[:MAX_SECONDARY_SYMBOLS]:
        provider["expanded_symbols"].append(symbol)
        for command, key, reason in (
            ("callers", "callers", "graph_reverse_caller"),
            ("impact", "affected", "graph_secondary_impact"),
        ):
            rc, rout, _ = run_cmd(
                ["codegraph", command, str(symbol), "--path", str(repo), "--json"],
                cwd=repo,
            )
            if rc != 0:
                continue
            try:
                result = json.loads(rout)
            except json.JSONDecodeError:
                continue
            items = [item for item in result.get(key, []) if isinstance(item, dict)]
            raw_edge_items.extend(items)
            selected_items = select_component_representative_items(
                repo,
                items,
                MAX_CG_EDGE_ITEMS_PER_GROUP,
                min_per_component=2,
                include_test_auxiliary=True,
                include_noisy_tests=False,
                include_build_artifacts=False,
            )
            selected_edge_items.extend(selected_items)
            provider[command if command != "impact" else "impact"].append(
                {"symbol": symbol, "items": selected_items, "reason": reason}
            )
    provider["selection"] = codegraph_selection_summary(
        repo,
        raw_changed_nodes,
        selected_changed_nodes,
        raw_edge_items,
        selected_edge_items,
    )
    if len(selected_changed_nodes) < len(raw_changed_nodes) or len(selected_edge_items) < len(raw_edge_items):
        provider["notes"].append(
            "CodeGraph roots/edge items were category-filtered, component-stratified, and security-scored before adapter truncation"
        )
    return provider


def build_context(repo: Path, worklist: Path, base: str) -> dict[str, Any]:
    rows = read_worklist(worklist)
    changed_files = [row.get("path", "") for row in rows if row.get("path")]
    supporting: dict[str, dict[str, Any]] = {}
    review_queue: dict[tuple[str, str, str], dict[str, Any]] = {}
    navigation_edges: list[dict[str, Any]] = []

    crg = code_review_graph_provider(repo, rows, base)
    extra_queries: list[str] = []
    for item in crg.get("review_priorities", []) + crg.get("changed_symbols", []):
        if isinstance(item, dict):
            extra_queries.extend(
                [
                    item.get("name", ""),
                    item.get("qualified_name", ""),
                    item.get("qualifiedName", ""),
                ]
            )
    cg = codegraph_provider(repo, rows, extra_queries)
    providers = [crg, cg]
    raw_artifacts: dict[str, Any] = {}
    raw_crg = crg.pop("_raw_detect_changes", None)
    if raw_crg is not None:
        raw_artifacts["code_review_graph_raw.json"] = raw_crg

    changed_symbols: list[dict[str, Any]] = []
    affected_flows: list[dict[str, Any]] = []
    test_gaps: list[dict[str, Any]] = []
    risk_score = None

    if crg.get("status") == "ok":
        risk_score = crg.get("risk_score")
        for item in crg.get("changed_symbols", []):
            changed_symbols.append({"provider": "code-review-graph", **item})
            symbol = node_name(item)
            file_value = item.get("file_path") or item.get("file")
            category = item.get("selection_category") or item_selection_category(repo, item)
            if category == "test_auxiliary":
                kind = "test_auxiliary"
                score = 35 + int(risk_value(item) * 35) + keyword_score(symbol, file_value or "")
                action = "Read only as auxiliary validation or attack-scenario harness context after production paths are reviewed."
            elif category == "config_supply_chain":
                kind = "config_supply_chain"
                score = 82 + int(risk_value(item) * 40) + keyword_score(symbol, file_value or "")
                action = "Review as build/config/supply-chain surface; bind findings to real runtime or delivery impact."
            else:
                kind = "changed_symbol"
                score = 80 + int(risk_value(item) * 50) + keyword_score(symbol, file_value or "")
                action = "Start here before ordinary file-order review; read the changed symbol and trace its source/control/sink behavior."
            add_review_queue_item(
                review_queue,
                repo,
                kind=kind,
                symbol=symbol,
                path_value=file_value,
                line=node_line(item),
                reason="Risk-scored changed function/class from code-review-graph",
                provider="code-review-graph",
                score=score,
                review_action=action,
            )
            add_supporting_file(
                supporting, repo, item.get("file_path") or item.get("file"),
                "graph_priority", "code-review-graph", item.get("name", ""),
            )
        for item in crg.get("review_priorities", []):
            symbol = node_name(item)
            file_value = item.get("file_path") or item.get("file")
            category = item.get("selection_category") or item_selection_category(repo, item)
            if category == "test_auxiliary":
                kind = "test_auxiliary"
                score = 40 + int(risk_value(item) * 35) + keyword_score(symbol, file_value or "")
                action = "Use as auxiliary integration/security test context; do not let it displace production source review."
            elif category == "config_supply_chain":
                kind = "config_supply_chain"
                score = 105 + int(risk_value(item) * 40) + keyword_score(symbol, file_value or "")
                action = "Review as build/config/supply-chain surface before ordinary file-order review."
            else:
                kind = "review_priority"
                score = 115 + int(risk_value(item) * 50) + keyword_score(symbol, file_value or "")
                action = "Read this provider-prioritized symbol early, then follow its direct callers/callees if relevant to the feature."
            add_review_queue_item(
                review_queue,
                repo,
                kind=kind,
                symbol=symbol,
                path_value=file_value,
                line=node_line(item),
                reason="Provider review priority; inspect before lower-risk changed files",
                provider="code-review-graph",
                score=score,
                review_action=action,
            )
            add_supporting_file(
                supporting, repo, item.get("file_path") or item.get("file"),
                "graph_priority", "code-review-graph", item.get("name", ""),
            )
        for gap in crg.get("test_gaps", []):
            test_gaps.append({"provider": "code-review-graph", **gap})
            symbol = node_name(gap)
            file_value = gap.get("file") or gap.get("file_path")
            category = gap.get("selection_category") or item_selection_category(repo, gap)
            if category in {"test_noisy", "test_auxiliary", "build_artifact"}:
                continue
            add_review_queue_item(
                review_queue,
                repo,
                kind="test_gap",
                symbol=symbol,
                path_value=file_value,
                line=node_line(gap),
                reason="Changed code has weak or missing test coverage signal",
                provider="code-review-graph",
                score=45 + keyword_score(symbol, file_value or ""),
                review_action="Use this as a validation gap signal after reviewing the corresponding changed symbol.",
            )
            add_supporting_file(
                supporting, repo, gap.get("file") or gap.get("file_path"),
                "graph_test_gap", "code-review-graph", gap.get("name", ""),
            )
        for flow in crg.get("affected_flows", []):
            affected_flows.append({"provider": "code-review-graph", **flow})
            for file_value in collect_file_values(flow):
                add_supporting_file(supporting, repo, file_value, "graph_flow", "code-review-graph")
                add_review_queue_item(
                    review_queue,
                    repo,
                    kind="affected_flow_file",
                    symbol=node_name(flow, "affected_flow"),
                    path_value=file_value,
                    line=None,
                    reason="File participates in provider affected flow",
                    provider="code-review-graph",
                    score=70 + keyword_score(node_name(flow), file_value),
                    review_action="Read as part of the affected execution flow before declaring the feature path covered.",
                )

    if cg.get("status") == "ok":
        for item in cg.get("changed_symbols", []):
            if isinstance(item, dict):
                changed_symbols.append({"provider": "codegraph", **item})
                symbol = node_name(item)
                file_value = item.get("filePath") or item.get("file_path")
                add_review_queue_item(
                    review_queue,
                    repo,
                    kind="changed_symbol",
                    symbol=symbol,
                    path_value=file_value,
                    line=node_line(item),
                    reason="CodeGraph matched a symbol from the changed worklist or provider priorities",
                    provider="codegraph",
                    score=90 + keyword_score(symbol, file_value or ""),
                    review_action="Use this symbol as a graph starting point; trace callers, callees, and impact before ordinary diff-file order.",
                )
                add_supporting_file(
                    supporting, repo, item.get("filePath") or item.get("file_path"),
                    "graph_priority", "codegraph", item.get("name", ""),
                )
        for group_key, reason in (("callers", "graph_caller"), ("callees", "graph_callee"), ("impact", "graph_impact")):
            for group in cg.get(group_key, []):
                group_symbol = group.get("symbol", "")
                group_reason = group.get("reason") or reason
                for item in group.get("items", []):
                    if isinstance(item, dict):
                        item_symbol = node_name(item)
                        file_value = item.get("filePath") or item.get("file_path") or item.get("file")
                        add_supporting_file(
                            supporting,
                            repo,
                            file_value,
                            reason,
                            "codegraph",
                            group_symbol,
                        )
                        edge = reason.replace("graph_", "")
                        add_navigation_edge(
                            navigation_edges,
                            repo,
                            provider="codegraph",
                            edge=edge,
                            from_symbol=group_symbol,
                            to_item=item,
                            reason=group_reason,
                        )
                        if reason == "graph_caller":
                            base_score = 88
                            kind = "caller_entrypoint"
                            action = "Read this caller before fallback file-order review; determine whether the changed symbol is reachable from a user or trust-boundary entrypoint."
                        elif reason == "graph_callee":
                            base_score = 86
                            kind = "callee_or_sink"
                            action = "Read this callee before fallback file-order review; check whether changed code reaches a shared sink/helper such as HTTP, file, auth, cache, or query logic."
                        else:
                            base_score = 62
                            kind = "impact_file"
                            action = "Read this impact-radius file if the feature path remains plausible after caller/callee tracing."
                        add_review_queue_item(
                            review_queue,
                            repo,
                            kind=kind,
                            symbol=item_symbol or group_symbol,
                            path_value=file_value,
                            line=node_line(item),
                            reason=f"{reason} of {group_symbol}",
                            provider="codegraph",
                            score=base_score + keyword_score(item_symbol, file_value or "", group_symbol),
                            review_action=action,
                        )

    # Avoid duplicating files already present in the worklist when computing added context.
    changed_set = set(changed_files)
    supporting_files = select_supporting_files(repo, supporting, changed_set, MAX_PROVIDER_FILES)
    selected_navigation_edges = select_navigation_edges(repo, navigation_edges, MAX_NAVIGATION_EDGES)

    ok_providers = [p for p in providers if p.get("status") == "ok"]
    graph_confidence = "none"
    if ok_providers:
        graph_confidence = "low"
    if supporting_files or changed_symbols:
        graph_confidence = "medium"
    if affected_flows or any("graph_caller" in f.get("reasons", []) for f in supporting_files):
        graph_confidence = "high"

    final_review_queue = finalize_review_queue(review_queue)
    status = "ok" if ok_providers else "unavailable"
    return {
        "status": status,
        "base": base,
        "worklist": str(worklist),
        "changed_files": changed_files,
        "providers": providers,
        "graph_confidence": graph_confidence,
        "graph_first_required": bool(final_review_queue),
        "risk_score": risk_score,
        "changed_symbols": changed_symbols[:MAX_CONTEXT_CHANGED_SYMBOLS],
        "graph_review_queue": final_review_queue,
        "navigation_edges": selected_navigation_edges,
        "affected_flows": affected_flows[:50],
        "test_gaps": test_gaps[:100],
        "supporting_files": supporting_files,
        "limitations": [
            "Graph output is context only; final findings still require source reads and validation.",
            "Provider indexes are not built automatically by this adapter.",
            "If graph_review_queue is non-empty, the audit should consume it before ordinary changed-file order.",
        ],
        "_raw_artifacts": raw_artifacts,
    }


def write_markdown(path: Path, context: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Graph Context",
        "",
        f"- Status: `{context.get('status')}`",
        f"- Base: `{context.get('base')}`",
        f"- Graph confidence: `{context.get('graph_confidence')}`",
        f"- Graph-first required: `{context.get('graph_first_required')}`",
        f"- Risk score: `{context.get('risk_score')}`",
        "",
        "## Raw Artifacts",
        "",
    ]
    raw_artifacts = context.get("raw_artifacts") or {}
    if raw_artifacts:
        for name, path_value in raw_artifacts.items():
            lines.append(f"- `{name}`: `{path_value}`")
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Providers",
        "",
        "| Provider | Status | Notes |",
        "|----------|--------|-------|",
    ])
    for provider in context.get("providers", []):
        notes = "; ".join(provider.get("notes") or [])
        lines.append(f"| {provider.get('name')} | {provider.get('status')} | {notes} |")
    lines.extend([
        "",
        "## Provider Selection Summary",
        "",
        "| Provider | Raw Changed | Selected Changed | Selected Categories | Selected Components | Excluded Tests | Excluded Build | Raw Test Ratio | Selected Test Ratio |",
        "|----------|-------------|------------------|---------------------|---------------------|----------------|----------------|----------------|---------------------|",
    ])
    for provider in context.get("providers", []):
        selection = provider.get("selection") or {}
        if not selection:
            continue
        selected_categories = ", ".join(f"{k}:{v}" for k, v in selection.get("selected_categories", {}).items())
        selected_components = ", ".join(f"{k}:{v}" for k, v in selection.get("selected_components", {}).items())
        lines.append(
            f"| {provider.get('name')} | {selection.get('raw_changed_symbols_count')} | "
            f"{selection.get('selected_changed_symbols_count')} | {selected_categories} | "
            f"{selected_components} | {selection.get('excluded_test_count')} | "
            f"{selection.get('excluded_build_artifact_count')} | {selection.get('raw_test_symbol_ratio')} | "
            f"{selection.get('selected_test_symbol_ratio')} |"
        )
    if not any((provider.get("selection") or {}) for provider in context.get("providers", [])):
        lines.append("| none | | | | | | | | |")
    lines.extend([
        "",
        "## Graph-First Review Queue",
        "",
        "| Priority | Kind | Symbol | File | Reason | Action |",
        "|----------|------|--------|------|--------|--------|",
    ])
    for item in context.get("graph_review_queue", []):
        symbol = item.get("symbol") or ""
        file_value = item.get("file") or ""
        if item.get("line"):
            file_value = f"{file_value}:{item.get('line')}" if file_value else str(item.get("line"))
        lines.append(
            f"| {item.get('priority')} | `{item.get('kind')}` | `{symbol}` | `{file_value}` | "
            f"{'; '.join(item.get('reasons', [])[:2])} | {item.get('review_action', '')} |"
        )
    if not context.get("graph_review_queue"):
        lines.append("| none | | | | | |")
    lines.extend([
        "",
        "## Navigation Edges",
        "",
        "| Edge | From | To | File | Reason |",
        "|------|------|----|------|--------|",
    ])
    for item in context.get("navigation_edges", [])[:40]:
        file_value = item.get("file") or ""
        if item.get("line"):
            file_value = f"{file_value}:{item.get('line')}" if file_value else str(item.get("line"))
        lines.append(
            f"| `{item.get('edge')}` | `{item.get('from')}` | `{item.get('to')}` | "
            f"`{file_value}` | {item.get('reason', '')} |"
        )
    if not context.get("navigation_edges"):
        lines.append("| none | | | | |")
    lines.extend([
        "",
        "## Supporting Files",
        "",
        "| File | Reasons | Providers | Details |",
        "|------|---------|-----------|---------|",
    ])
    for item in context.get("supporting_files", []):
        lines.append(
            f"| `{item['path']}` | {', '.join(item.get('reasons', []))} | "
            f"{', '.join(item.get('providers', []))} | {', '.join(item.get('details', [])[:3])} |"
        )
    if not context.get("supporting_files"):
        lines.append("| none | | | |")
    lines.extend([
        "",
        "## Affected Flows And Test Gaps",
        "",
        f"- Affected flows: {len(context.get('affected_flows', []))}",
        f"- Test gaps: {len(context.get('test_gaps', []))}",
        "",
        "## Limitations",
        "",
    ])
    for item in context.get("limitations", []):
        lines.append(f"- {item}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich audit worklists with optional code graph context.")
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--worklist", required=True, help="deep_review_input.csv path.")
    parser.add_argument("--base", default="HEAD", help="Git diff base for providers that need one.")
    parser.add_argument("--out-json", required=True, help="Machine-readable graph context output.")
    parser.add_argument("--out-md", required=True, help="Markdown graph context output.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo = Path(args.repo).resolve()
    worklist = Path(args.worklist).resolve()
    context = build_context(repo, worklist, args.base)
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    raw_artifacts = context.pop("_raw_artifacts", {}) or {}
    raw_artifact_paths: dict[str, str] = {}
    for filename, payload in raw_artifacts.items():
        raw_path = out_json.parent / filename
        raw_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        raw_artifact_paths[filename] = str(raw_path)
    if raw_artifact_paths:
        context["raw_artifacts"] = raw_artifact_paths
    out_json.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(Path(args.out_md), context)
    print(json.dumps({
        "status": context["status"],
        "graph_confidence": context["graph_confidence"],
        "graph_review_queue": len(context["graph_review_queue"]),
        "supporting_files": len(context["supporting_files"]),
    }))


if __name__ == "__main__":
    main()
