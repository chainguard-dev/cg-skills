#!/usr/bin/env python3
"""
rewrite_workflows.py — swap `uses:` action references to hardened equivalents.

This does a *line-targeted* replacement of the `uses:` value rather than parsing
and re-serializing the YAML. That is deliberate: round-tripping a workflow through
a YAML library destroys comments, key order, and formatting, which makes the diff
unreviewable and the PR noisy. A `uses:` value is always a simple scalar on its own
line, so a targeted edit is both safe and produces a minimal, reviewable diff.

It only ever changes the action reference. It never touches `with:` inputs, `env`,
permissions, or anything else — input compatibility between an upstream action and
its hardened replacement is the human reviewer's call, not this script's.

Input mapping (JSON), value is the FULL replacement ref so the source of truth
(chainctl discover / the catalog) decides the pin — we don't invent tags/SHAs:

    {
      "actions/checkout@v6":         "chainguard-actions/actions-checkout@v6.0.3",
      "docker/build-push-action":    "chainguard-actions/build-push-action@v6.10.0",
      "actions/setup-node@v4":       "chainguard-actions/actions-setup-node@v6.0.0"
    }

Keys may be a bare action NAME (owner/repo) or a version-qualified NAME@version.
For each `uses:` line, we compute its effective version (the @ref, or the version
from a trailing `# vX.Y.Z` comment when the ref is a bare SHA) and try
`name@version` first, then the bare `name`. This lets a mapping target only the
specific versions that are safe to swap — e.g. swapping actions/checkout@v6 while
leaving actions/checkout@v4 (a version gap) untouched. Matching is
case-insensitive (GitHub treats action owners/repos case-insensitively).

Usage:
    python rewrite_workflows.py --mapping mapping.json \
        --out-dir ./rewritten [WORKFLOW_FILE ...]
    # or scan a repo:
    python rewrite_workflows.py --mapping mapping.json --repo /path/to/repo \
        --out-dir ./rewritten

Outputs, per file: a rewritten copy under --out-dir (mirroring the relative path)
and a unified diff. Prints a JSON summary to stdout.
"""
import argparse
import difflib
import json
import os
import re
import sys

# Matches a `uses:` line, capturing:
#   1 = prefix up to and including `uses:` and following whitespace (incl. optional `- ` list marker)
#   2 = optional opening quote
#   3 = action name (owner/repo or owner/repo/subdir)
#   4 = optional @ref
#   5 = optional closing quote
#   6 = optional trailing whitespace + comment
USES_RE = re.compile(
    r'^(?P<prefix>\s*(?:-\s*)?uses:\s*)'
    r'(?P<q>["\']?)'
    r'(?P<name>[A-Za-z0-9._\-]+/[A-Za-z0-9._\-/]+?)'
    r'(?P<ref>@[^\s"\'#]+)?'
    r'(?P=q)'
    r'(?P<trailer>\s*(?:#.*)?)$'
)

# Effective version of a line: the @ref, or the comment version when SHA-pinned.
# Must match discover.py's logic so version-qualified mapping keys line up.
_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
_COMMENT_VER_RE = re.compile(r'#\s*(v?\d+(?:\.\d+){0,2}\S*)')


def _effective_version(ref, trailer):
    if ref and _SHA_RE.match(ref):
        m = _COMMENT_VER_RE.search(trailer or "")
        if m:
            return m.group(1)
    return ref


def load_mapping(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    # Normalize keys to lowercase for case-insensitive matching.
    norm = {}
    for k, v in raw.items():
        if not isinstance(v, str) or "/" not in v:
            raise ValueError(
                f"Mapping value for {k!r} must be a full replacement ref "
                f"like 'chainguard-actions/checkout@v4.2.2', got {v!r}"
            )
        norm[k.lower()] = v
    return norm


def rewrite_text(text, mapping):
    """Return (new_text, replacements) where replacements is a list of dicts."""
    out_lines = []
    replacements = []
    # Preserve original line endings by splitting on \n and tracking trailing newline.
    lines = text.split("\n")
    for i, line in enumerate(lines, start=1):
        m = USES_RE.match(line)
        if not m:
            out_lines.append(line)
            continue
        name = m.group("name")
        # Local actions (./path or ../path) and reusable-workflow file paths are
        # not catalog candidates — never touch them.
        if name.startswith((".", "/")):
            out_lines.append(line)
            continue
        old_ref = (m.group("ref") or "")[1:]  # strip leading @
        eff_ver = _effective_version(old_ref, m.group("trailer"))
        # Try the version-qualified key first, then the bare name.
        target, matched_key = None, None
        if eff_ver:
            matched_key = f"{name}@{eff_ver}".lower()
            target = mapping.get(matched_key)
        if target is None:
            matched_key = name.lower()
            target = mapping.get(matched_key)
        # Don't rewrite something already pointing at the hardened namespace.
        if target is None or name.lower().startswith("chainguard-actions/"):
            out_lines.append(line)
            continue
        new_line = f'{m.group("prefix")}{target}'
        out_lines.append(new_line)
        replacements.append(
            {
                "line": i,
                "from": name + (("@" + old_ref) if old_ref else ""),
                "to": target,
                "key": matched_key,
            }
        )
    return "\n".join(out_lines), replacements


def discover_workflow_files(repo):
    wf_dir = os.path.join(repo, ".github", "workflows")
    found = []
    if os.path.isdir(wf_dir):
        for entry in sorted(os.listdir(wf_dir)):
            if entry.endswith((".yml", ".yaml")):
                found.append(os.path.join(wf_dir, entry))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mapping", required=True, help="JSON mapping file")
    ap.add_argument("--out-dir", required=True, help="Where to write rewritten files")
    ap.add_argument("--repo", help="Repo root to auto-discover .github/workflows/*")
    ap.add_argument("files", nargs="*", help="Explicit workflow files to rewrite")
    ap.add_argument("--base-dir", help="Base dir for computing relative output paths "
                                       "(defaults to --repo or common path of files)")
    args = ap.parse_args(argv)

    mapping = load_mapping(args.mapping)

    files = list(args.files)
    if args.repo:
        files += discover_workflow_files(args.repo)
    files = [f for f in dict.fromkeys(files)]  # de-dupe, keep order
    if not files:
        print(json.dumps({"error": "no workflow files found"}), file=sys.stderr)
        return 2

    base = args.base_dir or args.repo
    os.makedirs(args.out_dir, exist_ok=True)

    summary = {"files": [], "total_replacements": 0,
               "unmatched_actions": {}}  # action name -> count (seen but not in mapping)

    # Track which mapping keys actually got used.
    used_keys = set()

    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        new_text, reps = rewrite_text(original, mapping)

        # Record any uses: that weren't covered, for visibility (same version-aware
        # lookup as rewrite_text, so a gap version left out of the mapping shows here).
        for line in original.split("\n"):
            mm = USES_RE.match(line)
            if mm:
                nm = mm.group("name")
                old_ref = (mm.group("ref") or "")[1:]
                eff_ver = _effective_version(old_ref, mm.group("trailer"))
                matched = (eff_ver and f"{nm}@{eff_ver}".lower() in mapping) or nm.lower() in mapping
                if (not nm.startswith((".", "/"))
                        and not matched
                        and not nm.lower().startswith("chainguard-actions/")):
                    key = nm + (f"@{eff_ver}" if eff_ver else "")
                    summary["unmatched_actions"][key] = summary["unmatched_actions"].get(key, 0) + 1

        for r in reps:
            used_keys.add(r["key"])

        if base:
            rel = os.path.relpath(path, base)
        else:
            rel = os.path.basename(path)
        out_path = os.path.join(args.out_dir, rel)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(new_text)

        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=rel,
                tofile=rel + " (hardened)",
            )
        )
        diff_path = out_path + ".diff"
        if reps:
            with open(diff_path, "w", encoding="utf-8") as f:
                f.write(diff)

        summary["files"].append(
            {
                "path": path,
                "rewritten": out_path,
                "diff": diff_path if reps else None,
                "replacements": reps,
            }
        )
        summary["total_replacements"] += len(reps)

    summary["mapping_keys_unused"] = sorted(
        k for k in mapping if k not in used_keys
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
