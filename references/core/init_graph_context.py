#!/usr/bin/env python3
"""Prepare optional graph databases before Git incremental security review.

This script is meant to be run from the audit framework or by a human before
starting /git-audit. It writes only target-repository local metadata:

- .git/info/exclude entries for graph/audit artifacts
- .codegraph/ via codegraph
- .code-review-graph/ via code-review-graph

It does not install tools. Missing tools are reported and skipped unless
--strict is used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = int(os.environ.get("AUDIT_GRAPH_INIT_TIMEOUT", "300"))
EXCLUDE_LINES = [".codegraph/", ".code-review-graph/", ".audit-work/", "audit-reports/"]


def run_cmd(args: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
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
        return {
            "command": " ".join(shlex.quote(a) for a in args),
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": " ".join(shlex.quote(a) for a in args),
            "returncode": 124,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": f"timeout after {timeout}s",
        }
    except OSError as exc:
        return {
            "command": " ".join(shlex.quote(a) for a in args),
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }


def resolve_repo(path: str) -> Path:
    repo = Path(path).expanduser().resolve()
    if not repo.exists():
        raise SystemExit(f"repo does not exist: {repo}")
    if not repo.is_dir():
        raise SystemExit(f"repo is not a directory: {repo}")
    return repo


def git_dir(repo: Path, timeout: int) -> Path | None:
    result = run_cmd(["git", "rev-parse", "--git-dir"], repo, timeout)
    if result["returncode"] != 0 or not result["stdout"]:
        return None
    value = Path(result["stdout"].splitlines()[-1])
    if value.is_absolute():
        return value
    return (repo / value).resolve()


def ensure_local_exclude(repo: Path, timeout: int, dry_run: bool, skip: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": None,
        "status": "skipped" if skip else "unknown",
        "added": [],
        "present": [],
        "notes": [],
    }
    if skip:
        result["notes"].append("--skip-exclude was used")
        return result

    gd = git_dir(repo, timeout)
    if gd is None:
        result["status"] = "skipped"
        result["notes"].append("target is not a Git worktree")
        return result

    exclude_path = gd / "info" / "exclude"
    result["path"] = str(exclude_path)
    existing = ""
    if exclude_path.exists():
        existing = exclude_path.read_text(encoding="utf-8", errors="replace")

    existing_lines = {line.strip() for line in existing.splitlines()}
    missing = [line for line in EXCLUDE_LINES if line not in existing_lines]
    result["present"] = [line for line in EXCLUDE_LINES if line in existing_lines]
    result["added"] = missing

    if dry_run:
        result["status"] = "dry_run"
        return result

    if missing:
        exclude_path.parent.mkdir(parents=True, exist_ok=True)
        prefix = "" if existing.endswith("\n") or not existing else "\n"
        with exclude_path.open("a", encoding="utf-8") as handle:
            handle.write(prefix)
            handle.write("# Audit graph context artifacts\n")
            for line in missing:
                handle.write(f"{line}\n")
        result["status"] = "updated"
    else:
        result["status"] = "ok"
    return result


def parse_code_review_status(stdout: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    patterns = {
        "nodes": r"^Nodes:\s*(\d+)",
        "edges": r"^Edges:\s*(\d+)",
        "files": r"^Files:\s*(\d+)",
        "languages": r"^Languages:[ \t]*(.*)$",
        "last_updated": r"^Last updated:[ \t]*(.*)$",
        "built_on_branch": r"^Built on branch:[ \t]*(.*)$",
        "built_at_commit": r"^Built at commit:[ \t]*(.*)$",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, stdout, re.MULTILINE)
        if not match:
            continue
        value: Any = match.group(1).strip()
        if key in {"nodes", "edges", "files"}:
            value = int(value)
        parsed[key] = value
    return parsed


def codegraph_status(repo: Path, timeout: int) -> dict[str, Any]:
    result = run_cmd(["codegraph", "status", str(repo), "--json"], repo, timeout)
    status: dict[str, Any] = {
        "command": result["command"],
        "returncode": result["returncode"],
        "initialized": False,
        "status": "error" if result["returncode"] else "ok",
        "summary": {},
        "stdout": result["stdout"][:2000],
        "stderr": result["stderr"][:2000],
    }
    if result["returncode"] != 0:
        return status
    try:
        data = json.loads(result["stdout"])
    except json.JSONDecodeError:
        status["status"] = "error"
        status["stderr"] = "codegraph status did not return JSON"
        return status
    status["initialized"] = bool(data.get("initialized"))
    status["summary"] = {
        "file_count": data.get("fileCount"),
        "node_count": data.get("nodeCount"),
        "edge_count": data.get("edgeCount"),
        "languages": data.get("languages"),
        "pending_changes": data.get("pendingChanges"),
        "worktree_mismatch": data.get("worktreeMismatch"),
    }
    return status


def code_review_graph_status(repo: Path, timeout: int) -> dict[str, Any]:
    graph_db = repo / ".code-review-graph" / "graph.db"
    if not graph_db.exists():
        return {
            "command": "code-review-graph status --repo " + shlex.quote(str(repo)),
            "returncode": None,
            "initialized": False,
            "status": "not_indexed",
            "summary": {},
            "stdout": "",
            "stderr": ".code-review-graph/graph.db not found",
        }

    result = run_cmd(["code-review-graph", "status", "--repo", str(repo)], repo, timeout)
    initialized = graph_db.exists() and result["returncode"] == 0
    return {
        "command": result["command"],
        "returncode": result["returncode"],
        "initialized": initialized,
        "status": "ok" if initialized else ("not_indexed" if result["returncode"] == 0 else "error"),
        "summary": parse_code_review_status(result["stdout"]),
        "stdout": result["stdout"][:2000],
        "stderr": result["stderr"][:2000],
    }


def prepare_codegraph(repo: Path, mode: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    provider: dict[str, Any] = {
        "name": "codegraph",
        "available": shutil.which("codegraph") is not None,
        "status": "missing",
        "action": "none",
        "before": None,
        "after": None,
        "run": None,
        "notes": [],
    }
    if not provider["available"]:
        provider["notes"].append("codegraph CLI not found on PATH")
        return provider

    before = codegraph_status(repo, timeout)
    provider["before"] = before
    if mode == "status":
        provider["status"] = before["status"]
        provider["after"] = before
        return provider

    initialized = bool(before.get("initialized"))
    if mode == "init" and initialized:
        provider["status"] = "ok"
        provider["action"] = "already_initialized"
        provider["after"] = before
        return provider

    command = ["codegraph", "sync", str(repo)] if initialized else ["codegraph", "init", str(repo)]
    provider["action"] = "sync" if initialized else "init"
    if dry_run:
        provider["status"] = "dry_run"
        provider["run"] = {"command": " ".join(shlex.quote(a) for a in command), "returncode": None}
        provider["after"] = before
        return provider

    run = run_cmd(command, repo, timeout)
    provider["run"] = {
        "command": run["command"],
        "returncode": run["returncode"],
        "stdout": run["stdout"][-2000:],
        "stderr": run["stderr"][-2000:],
    }
    provider["after"] = codegraph_status(repo, timeout)
    provider["status"] = "ok" if run["returncode"] == 0 and provider["after"].get("initialized") else "error"
    return provider


def prepare_code_review_graph(repo: Path, mode: str, timeout: int, dry_run: bool) -> dict[str, Any]:
    provider: dict[str, Any] = {
        "name": "code-review-graph",
        "available": shutil.which("code-review-graph") is not None,
        "status": "missing",
        "action": "none",
        "before": None,
        "after": None,
        "run": None,
        "notes": [],
    }
    if not provider["available"]:
        provider["notes"].append("code-review-graph CLI not found on PATH")
        return provider

    before = code_review_graph_status(repo, timeout)
    provider["before"] = before
    if mode == "status":
        provider["status"] = before["status"]
        provider["after"] = before
        return provider

    initialized = bool(before.get("initialized"))
    if mode == "init" and initialized:
        provider["status"] = "ok"
        provider["action"] = "already_initialized"
        provider["after"] = before
        return provider

    command = (
        ["code-review-graph", "update", "--repo", str(repo)]
        if initialized
        else ["code-review-graph", "build", "--repo", str(repo)]
    )
    provider["action"] = "update" if initialized else "build"
    if dry_run:
        provider["status"] = "dry_run"
        provider["run"] = {"command": " ".join(shlex.quote(a) for a in command), "returncode": None}
        provider["after"] = before
        return provider

    run = run_cmd(command, repo, timeout)
    provider["run"] = {
        "command": run["command"],
        "returncode": run["returncode"],
        "stdout": run["stdout"][-2000:],
        "stderr": run["stderr"][-2000:],
    }
    provider["after"] = code_review_graph_status(repo, timeout)
    provider["status"] = "ok" if run["returncode"] == 0 and provider["after"].get("initialized") else "error"
    return provider


def selected_providers(value: str) -> set[str]:
    aliases = {
        "both": {"codegraph", "code-review-graph"},
        "all": {"codegraph", "code-review-graph"},
        "codegraph": {"codegraph"},
        "code-review-graph": {"code-review-graph"},
        "crg": {"code-review-graph"},
    }
    selected: set[str] = set()
    for item in value.split(","):
        key = item.strip().lower()
        if not key:
            continue
        if key not in aliases:
            raise SystemExit(f"unknown provider: {item}")
        selected.update(aliases[key])
    return selected or aliases["both"]


def provider_line(provider: dict[str, Any]) -> str:
    after = provider.get("after") or {}
    summary = after.get("summary") or {}
    bits = [
        f"{provider['name']}: status={provider['status']}",
        f"action={provider['action']}",
    ]
    if provider["name"] == "codegraph":
        if summary.get("file_count") is not None:
            bits.append(f"files={summary.get('file_count')}")
        if summary.get("node_count") is not None:
            bits.append(f"nodes={summary.get('node_count')}")
        if summary.get("edge_count") is not None:
            bits.append(f"edges={summary.get('edge_count')}")
    else:
        if summary.get("files") is not None:
            bits.append(f"files={summary.get('files')}")
        if summary.get("nodes") is not None:
            bits.append(f"nodes={summary.get('nodes')}")
        if summary.get("edges") is not None:
            bits.append(f"edges={summary.get('edges')}")
    if provider.get("notes"):
        bits.append("notes=" + "; ".join(provider["notes"]))
    return "  - " + ", ".join(bits)


def print_human(result: dict[str, Any]) -> None:
    print("Graph Context Initialization")
    print(f"repo: {result['repo_root']}")
    print(f"mode: {result['mode']}")
    exclude = result["exclude"]
    print(f"exclude: status={exclude['status']} path={exclude.get('path') or 'n/a'}")
    if exclude.get("added"):
        print(f"  added: {', '.join(exclude['added'])}")
    for provider in result["providers"]:
        print(provider_line(provider))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize or update codegraph/code-review-graph databases in a target repository."
    )
    parser.add_argument("--repo", default=".", help="Target repository root. Defaults to current directory.")
    parser.add_argument(
        "--mode",
        choices=["status", "init", "update"],
        default="update",
        help="status=inspect only, init=build missing only, update=init missing or incrementally update existing.",
    )
    parser.add_argument(
        "--providers",
        default="both",
        help="Provider list: both, codegraph, code-review-graph, or comma-separated values.",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-command timeout in seconds.")
    parser.add_argument("--skip-exclude", action="store_true", help="Do not write .git/info/exclude entries.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned actions without running build/update.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero for missing providers too.")
    parser.add_argument("--json", action="store_true", help="Print JSON result.")
    args = parser.parse_args(argv)

    repo = resolve_repo(args.repo)
    selected = selected_providers(args.providers)
    result: dict[str, Any] = {
        "repo_root": str(repo),
        "mode": args.mode,
        "dry_run": args.dry_run,
        "exclude": ensure_local_exclude(
            repo,
            args.timeout,
            args.dry_run or args.mode == "status",
            args.skip_exclude,
        ),
        "providers": [],
    }

    if "codegraph" in selected:
        result["providers"].append(prepare_codegraph(repo, args.mode, args.timeout, args.dry_run))
    if "code-review-graph" in selected:
        result["providers"].append(prepare_code_review_graph(repo, args.mode, args.timeout, args.dry_run))

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)

    statuses = [provider["status"] for provider in result["providers"]]
    if any(status == "error" for status in statuses):
        return 1
    if args.strict and any(status in {"missing", "not_indexed"} for status in statuses):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
