#!/usr/bin/env python3
"""
scan_workflows.py — FALLBACK action discovery from local repo clones.

Prefer `chainctl actions discover` (it's the product, and it knows the catalog).
Use this only when discover isn't available — e.g. the org isn't entitled yet, or
you're doing an offline gap analysis on clones you already have on disk.

It walks one or more repo roots, finds .github/workflows/*.{yml,yaml}, extracts
every `uses:` reference, and emits the canonical inventory.json that
summarize_inventory.py and rewrite_workflows.py consume. It does NOT know which
actions have hardened equivalents — every entry's hardened fields are left null
for a later catalog-resolution step to fill in.

Usage:
    python scan_workflows.py --org acme REPO_ROOT [REPO_ROOT ...] > inventory.json
    # REPO_ROOT may be a single repo, or a parent dir containing many repos.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

USES_RE = re.compile(
    r'^(?P<prefix>\s*(?:-\s*)?uses:\s*)'
    r'(?P<q>["\']?)'
    r'(?P<name>[A-Za-z0-9._\-]+/[A-Za-z0-9._\-/]+?)'
    r'(?P<ref>@[^\s"\'#]+)?'
    r'(?P=q)'
    r'(?P<trailer>\s*(?:#.*)?)$'
)


def find_repos(root):
    """If root itself has .github/workflows, it's a repo. Otherwise treat its
    immediate subdirectories as repos."""
    if os.path.isdir(os.path.join(root, ".github", "workflows")):
        return [root]
    repos = []
    for entry in sorted(os.listdir(root)):
        p = os.path.join(root, entry)
        if os.path.isdir(os.path.join(p, ".github", "workflows")):
            repos.append(p)
    return repos


def scan_repo(repo_path):
    """Yield (workflow_rel_path, name, ref, line) for each uses: in the repo."""
    root = Path(repo_path).resolve()
    wf_dir = root / ".github" / "workflows"
    for entry in sorted(wf_dir.iterdir()):
        if not entry.name.endswith((".yml", ".yaml")):
            continue
        # A cloned repo is untrusted: a symlinked workflow (or workflows dir)
        # could point anywhere on this machine, so read only what stays inside it.
        try:
            wf_path = entry.resolve(strict=True)
        except (OSError, RuntimeError) as e:  # loop or dangling link; 3.9-3.12 raise RuntimeError
            print(f"warning: skipping {entry.relative_to(root)}: cannot resolve: {e}",
                  file=sys.stderr)
            continue
        if not wf_path.is_relative_to(root):
            print(f"warning: skipping {entry.relative_to(root)}: resolves outside {root}",
                  file=sys.stderr)
            continue
        if not wf_path.is_file():
            continue
        rel = os.path.join(".github", "workflows", entry.name)
        with open(wf_path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                m = USES_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                name = m.group("name")
                if name.startswith((".", "/")):  # local action / reusable wf path
                    continue
                ref = (m.group("ref") or "")[1:]
                yield rel, name, ref, i


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", default=None, help="Org label for the report")
    ap.add_argument("roots", nargs="+", help="Repo root(s) or a parent dir of repos")
    args = ap.parse_args(argv)

    repos = []
    for root in args.roots:
        repos.extend(find_repos(root))
    if not repos:
        print(json.dumps({"error": "no repos with .github/workflows found"}),
              file=sys.stderr)
        return 2

    actions = {}  # name -> {"occurrences": [...]}
    for repo in repos:
        repo_label = os.path.basename(os.path.normpath(repo))
        if args.org:
            repo_label = f"{args.org}/{repo_label}"
        for wf, name, ref, line in scan_repo(repo):
            actions.setdefault(name, {"occurrences": []})
            actions[name]["occurrences"].append(
                {"repo": repo_label, "workflow": wf, "ref": ref, "line": line}
            )

    inventory = {
        "org": args.org,
        "generated_by": "workflow-scan",
        "actions": [
            {
                "name": name,
                "occurrences": data["occurrences"],
                "hardened_available": None,  # unknown — resolve against catalog
                "hardened_ref": None,
            }
            for name, data in sorted(actions.items())
        ],
    }
    print(json.dumps(inventory, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
