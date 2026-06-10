#!/usr/bin/env python3
"""Generate deterministic worklists for feature-centric Git incremental security review."""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import subprocess
from pathlib import Path


SOURCE_LIKE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".clj",
    ".cpp",
    ".cs",
    ".css",
    ".cue",
    ".cxx",
    ".dart",
    ".ex",
    ".exs",
    ".go",
    ".graphql",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".mjs",
    ".php",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

SECURITY_RELEVANT_FILENAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "gemfile",
    "gemfile.lock",
}

SECURITY_PATH_HINTS = (
    ".codex/agents/",
    ".codex/skills/",
    ".claude/agents/",
    ".opencode/agents/",
    ".opencode/skills/",
    ".github/workflows/",
    "ci/",
    "deploy/",
    "docker/",
    "k8s/",
    "kubernetes/",
    "terraform/",
    "helm/",
)

EXCLUDED_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "build",
    "dist",
    "target",
    "coverage",
    ".cache",
    ".code-review-graph",
    ".codegraph",
    ".pytest_cache",
    ".mypy_cache",
    "audit-output",
}


def run_git(repo: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def is_source_like(path: str) -> bool:
    p = Path(path)
    if p.name.lower() in SECURITY_RELEVANT_FILENAMES:
        return True
    return p.suffix.lower() in SOURCE_LIKE_EXTENSIONS


def is_security_relevant(path: str) -> bool:
    lowered = path.lower()
    if Path(lowered).name in SECURITY_RELEVANT_FILENAMES:
        return True
    return lowered.startswith(SECURITY_PATH_HINTS) or is_source_like(path)


def excluded_reason(path: str) -> str:
    parts = Path(path).parts
    for part in parts:
        if part in EXCLUDED_DIRS:
            return f"excluded_dir:{part}"
    return ""


def preview_for(repo: Path, path: str, preview_bytes: int) -> str:
    target = repo / path
    if not target.exists() or not target.is_file():
        return ""
    try:
        data = target.read_bytes()[:preview_bytes]
    except OSError:
        return ""
    if b"\0" in data:
        return ""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def parse_name_status(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        old_path = ""
        if status.startswith("R") or status.startswith("C"):
            old_path = parts[1] if len(parts) > 2 else ""
            path = parts[2] if len(parts) > 2 else parts[-1]
        else:
            path = parts[1] if len(parts) > 1 else parts[-1]
        rows.append({"path": path, "status": status, "old_path": old_path})
    return rows


HUNK_RE = re.compile(r"^\+\+\+ b/(.+)$|^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def hunk_map(diff_text: str) -> dict[str, list[str]]:
    current = ""
    hunks: dict[str, list[str]] = {}
    for line in diff_text.splitlines():
        file_match = re.match(r"^\+\+\+ b/(.+)$", line)
        if file_match:
            current = file_match.group(1)
            hunks.setdefault(current, [])
            continue
        hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if current and hunk_match:
            start = int(hunk_match.group(1))
            length = int(hunk_match.group(2) or "1")
            end = start + max(length, 1) - 1
            hunks.setdefault(current, []).append(f"{start}-{end}")
    return hunks


def changed_rows_for_revisions(repo: Path, base: str, head: str) -> list[dict[str, str]]:
    name_status = run_git(repo, ["diff", "--name-status", base, head])
    rows = parse_name_status(name_status)
    diff_text = run_git(repo, ["diff", "--unified=0", base, head])
    hunks = hunk_map(diff_text)
    for row in rows:
        row["hunks"] = ";".join(hunks.get(row["path"], []))
    return rows


def changed_rows_for_worktree(repo: Path, mode: str) -> list[dict[str, str]]:
    if mode == "staged":
        name_status = run_git(repo, ["diff", "--cached", "--name-status"])
        diff_text = run_git(repo, ["diff", "--cached", "--unified=0"])
    elif mode == "unstaged":
        name_status = run_git(repo, ["diff", "--name-status"])
        diff_text = run_git(repo, ["diff", "--unified=0"])
    else:
        name_status = run_git(repo, ["diff", "--name-status", "HEAD"])
        diff_text = run_git(repo, ["diff", "--unified=0", "HEAD"])
    rows = parse_name_status(name_status)
    hunks = hunk_map(diff_text)
    for row in rows:
        row["hunks"] = ";".join(hunks.get(row["path"], []))
    if mode in {"worktree", "unstaged"}:
        tracked_paths = {row["path"] for row in rows}
        untracked = run_git(repo, ["ls-files", "--others", "--exclude-standard"])
        for path in [p.strip() for p in untracked.splitlines() if p.strip()]:
            if path not in tracked_paths:
                rows.append({"path": path, "status": "A?", "old_path": "", "hunks": ""})
    return rows


def changed_rows_for_patch(repo: Path, patch: Path) -> list[dict[str, str]]:
    try:
        text = patch.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit(f"cannot read patch {patch}: {exc}")
    files: dict[str, dict[str, str]] = {}
    hunks = hunk_map(text)
    current = ""
    for line in text.splitlines():
        match = re.match(r"^\+\+\+ b/(.+)$", line)
        if match:
            current = match.group(1)
            files.setdefault(current, {"path": current, "status": "PATCH", "old_path": ""})
    for path, row in files.items():
        row["hunks"] = ";".join(hunks.get(path, []))
    return list(files.values())


def changed_rows_for_commits(repo: Path, commits: str) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for commit in [c.strip() for c in commits.split(",") if c.strip()]:
        for row in changed_rows_for_revisions(repo, f"{commit}^", commit):
            path = row["path"]
            existing = merged.get(path)
            if not existing:
                merged[path] = row
                continue
            existing_hunks = set(filter(None, existing.get("hunks", "").split(";")))
            row_hunks = set(filter(None, row.get("hunks", "").split(";")))
            existing["hunks"] = ";".join(sorted(existing_hunks | row_hunks))
            if row.get("status") and row["status"] not in existing.get("status", ""):
                existing["status"] = f"{existing.get('status', '')},{row['status']}"
    return list(merged.values())


def merge_base(repo: Path, base: str, head: str) -> str:
    return run_git(repo, ["merge-base", base, head]).strip()


def enrich_rows(repo: Path, rows: list[dict[str, str]], area: str, preview_bytes: int) -> list[dict[str, str]]:
    enriched = []
    seen: set[str] = set()
    for row in rows:
        path = row["path"]
        if path in seen:
            continue
        seen.add(path)
        reason = excluded_reason(path)
        enriched.append(
            {
                "path": path,
                "status": row.get("status", ""),
                "area": area,
                "is_source_like": "yes" if is_source_like(path) else "no",
                "is_security_relevant": "yes" if is_security_relevant(path) else "no",
                "old_path": row.get("old_path", ""),
                "hunks": row.get("hunks", ""),
                "preview": preview_for(repo, path, preview_bytes),
                "exclude_reason": reason,
            }
        )
    enriched.sort(key=lambda r: r["path"])
    return enriched


def write_diff_worklist(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "path",
                "status",
                "area",
                "is_source_like",
                "is_security_relevant",
                "old_path",
                "hunks",
                "preview",
                "exclude_reason",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_deep_review(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "area", "reason", "hunks"])
        writer.writeheader()
        for row in rows:
            if row["exclude_reason"]:
                continue
            if row["is_source_like"] == "yes" or row["is_security_relevant"] == "yes":
                writer.writerow(
                    {
                        "path": row["path"],
                        "area": row["area"],
                        "reason": "source_like" if row["is_source_like"] == "yes" else "security_relevant",
                        "hunks": row["hunks"],
                    }
                )


def scope_hash(rows: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(row["path"].encode())
        digest.update(row.get("hunks", "").encode())
        digest.update(row.get("status", "").encode())
    return digest.hexdigest()[:12]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Git incremental security review worklists.")
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--out", required=True, help="diff_worklist.csv output path.")
    parser.add_argument("--deep-out", required=True, help="deep_review_input.csv output path.")
    parser.add_argument("--area", default="feature-diff", help="Area label.")
    parser.add_argument("--preview-bytes", type=int, default=200)
    parser.add_argument("--print-scope-hash", action="store_true")

    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument("--worktree", action="store_true")
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--unstaged", action="store_true")
    mode.add_argument("--commit")
    mode.add_argument("--commits")
    mode.add_argument("--range")
    mode.add_argument("--patch")
    mode.add_argument("--merge-base", nargs=2, metavar=("BASE", "HEAD"))
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"not a Git repository: {repo}")

    if args.worktree:
        rows = changed_rows_for_worktree(repo, "worktree")
    elif args.staged:
        rows = changed_rows_for_worktree(repo, "staged")
    elif args.unstaged:
        rows = changed_rows_for_worktree(repo, "unstaged")
    elif args.commit:
        rows = changed_rows_for_revisions(repo, f"{args.commit}^", args.commit)
    elif args.commits:
        rows = changed_rows_for_commits(repo, args.commits)
    elif args.range:
        if ".." not in args.range:
            raise SystemExit("--range must use base..head")
        base, head = args.range.split("..", 1)
        rows = changed_rows_for_revisions(repo, base, head)
    elif args.patch:
        rows = changed_rows_for_patch(repo, Path(args.patch).resolve())
    elif args.merge_base:
        base_ref, head_ref = args.merge_base
        rows = changed_rows_for_revisions(repo, merge_base(repo, base_ref, head_ref), head_ref)
    else:
        base = args.base
        if not base:
            raise SystemExit("provide one of --worktree, --staged, --unstaged, --commit, --commits, --range, --patch, --merge-base, or --base")
        rows = changed_rows_for_revisions(repo, base, args.head)

    enriched = enrich_rows(repo, rows, args.area, args.preview_bytes)
    write_diff_worklist(Path(args.out), enriched)
    write_deep_review(Path(args.deep_out), enriched)
    if args.print_scope_hash:
        print(scope_hash(enriched))


if __name__ == "__main__":
    main()
