#!/usr/bin/env python3
"""
discover.py — discover GitHub Actions usage and resolve Chainguard hardened equivalents.

PRIMARY MODE: fetches workflow files via the GitHub API (no clone, no chainctl).
Requires only: gh CLI authenticated (gh auth login).

LIST MODE (--actions-list): resolve a pasted or file-provided list of actions
without any GitHub repo access. Useful for quick lookups or when a customer
shares their action list manually.

FUTURE — chainctl integration (two independent pieces, both pending):

  1. CATALOG LOOKUP  →  chainctl actions catalog list -o json
     Authoritative list of every hardened action Chainguard publishes.
     As of 2026-06 the command exists but the API returns null (in development).
     When live: call once at startup, build a dict
       {upstream_action: (chainguard_repo, [tags_desc])}
     then replace get_hardened_tags() with a dict lookup — same return signature,
     no downstream changes needed.  Flags: --upstream-owner, --upstream-repo.

  2. REPO SCANNING  →  chainctl actions discover <owner/repo> -o json
     Handles composite action dependencies transitively (gh API does not).
     Output: {"nodes": {ref: {requested_version, dep_of[]}}, "edges": {}}
     Blocker: no line numbers in output. rewrite_workflows.py needs line numbers
     to do targeted substitution.  When chainctl adds line numbers, replace
     scan_repo() — same yield signature (wf_path, name, ref, lineno).
     Org listing has no chainctl equivalent; gh CLI stays for that.

Usage:
    python3 discover.py owner/repo                          > inventory.json
    python3 discover.py owner/repo1 owner/repo2             > inventory.json
    python3 discover.py --org myorg                         > inventory.json
    python3 discover.py owner/repo --version-strategy latest > inventory.json
    python3 discover.py --actions-list actions.txt          > inventory.json
    python3 discover.py --actions-list -                    > inventory.json
    echo "actions/checkout@v4" | python3 discover.py --actions-list -

    Actions list format (auto-detected):
      actions/checkout@v4        (one per line, name@ref)
      actions/checkout           (no version)
      actions/checkout, v4       (CSV)
      name,ref                   (CSV with header — header is skipped)
      # comment lines are ignored
"""
import argparse
import base64
import json
import re
import subprocess
import sys
from collections import defaultdict

USES_RE = re.compile(
    r'^(?P<prefix>\s*(?:-\s*)?uses:\s*)'
    r'(?P<q>["\']?)'
    r'(?P<name>[A-Za-z0-9._\-]+/[A-Za-z0-9._\-/]+?)'
    r'(?P<ref>@[^\s"\'#]+)?'
    r'(?P=q)'
    r'(?P<trailer>\s*(?:#.*)?)$'
)

# Versions are usually SHA-pinned with a human version in a trailing comment, e.g.
#   uses: actions/checkout@<sha>   # v4.1.2
# Pull that comment version out for display ("versions in use" is unreadable as SHAs).
_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
_COMMENT_VER_RE = re.compile(r'#\s*(v?\d+(?:\.\d+){0,2}\S*)')


def _display_version(ref, trailer):
    """Human-friendly version: comment version when the ref is a bare SHA, else the ref."""
    if ref and _SHA_RE.match(ref):
        m = _COMMENT_VER_RE.search(trailer or "")
        if m:
            return m.group(1)
    return ref


# ---------------------------------------------------------------------------
# GitHub API helpers (gh CLI)
# ---------------------------------------------------------------------------

def _gh(*args, check=True):
    result = subprocess.run(["gh", "api"] + list(args), capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result


def list_org_repos(org):
    result = subprocess.run(
        ["gh", "repo", "list", org, "--limit", "500",
         "--json", "nameWithOwner", "--jq", ".[].nameWithOwner"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"warning: could not list repos for {org}: {result.stderr.strip()}", file=sys.stderr)
        return []
    return [l.strip() for l in result.stdout.splitlines() if l.strip()]


def list_workflow_files(owner_repo):
    # Fetch the directory listing and filter in Python. (Doing the .yml/.yaml
    # filter in jq requires a regex with an escaped dot, and jq's JSON string
    # parser rejects a lone "\." — escaping it portably across shells/jq
    # versions is fragile, so we filter here instead.)
    r = _gh(
        f"repos/{owner_repo}/contents/.github/workflows",
        "--jq", '[.[] | select(.type=="file") | .path]',
        check=False,
    )
    if r.returncode != 0:
        return []
    try:
        paths = json.loads(r.stdout)
    except (json.JSONDecodeError, TypeError):
        return []
    return [p for p in paths if isinstance(p, str) and p.lower().endswith((".yml", ".yaml"))]


def fetch_file_lines(owner_repo, path):
    r = _gh(f"repos/{owner_repo}/contents/{path}", "--jq", ".content", check=False)
    if r.returncode != 0:
        return []
    try:
        return base64.b64decode(r.stdout.strip().strip('"')).decode("utf-8", errors="replace").splitlines()
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Workflow scanning
# ---------------------------------------------------------------------------

def _extract_uses(lines):
    """Yield (action_name, ref, version, line_number) for each uses: in a list of lines."""
    for i, line in enumerate(lines, start=1):
        m = USES_RE.match(line)
        if not m:
            continue
        name = m.group("name")
        if name.startswith((".", "/")):
            continue
        ref = (m.group("ref") or "")[1:]
        version = _display_version(ref, m.group("trailer"))
        yield name, ref, version, i


def scan_repo(owner_repo):
    """Yield (workflow_path, action_name, ref, version, line_number) for each uses:."""
    # FUTURE: replace with chainctl actions discover once it includes line numbers
    # (see module docstring piece 2).
    for wf_path in list_workflow_files(owner_repo):
        lines = fetch_file_lines(owner_repo, wf_path)
        for name, ref, version, i in _extract_uses(lines):
            yield wf_path, name, ref, version, i


def scan_local_dir(root):
    """
    Yield (workflow_path, action_name, ref, line_number) for a local checkout.

    `root` is a directory; scans <root>/.github/workflows/*.{yml,yaml}. Paths in
    the output are relative to root so they match what rewrite_workflows.py expects.
    """
    import os
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return
    for fname in sorted(os.listdir(wf_dir)):
        if not fname.lower().endswith((".yml", ".yaml")):
            continue
        full = os.path.join(wf_dir, fname)
        if not os.path.isfile(full):
            continue
        rel = os.path.join(".github", "workflows", fname)
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        for name, ref, version, i in _extract_uses(lines):
            yield rel, name, ref, version, i


# ---------------------------------------------------------------------------
# Catalog resolution (gh API fallback until chainctl catalog is live)
# ---------------------------------------------------------------------------

def _is_public_action_repo(candidate):
    """
    True only if `candidate` (owner/repo) exists and is PUBLIC and not archived.

    This is the guard against recommending private, in-development chainguard-actions
    repos. A token belonging to a Chainguard employee can read private repos that
    don't exist for customers, so a plain tags lookup would mark them "available"
    and produce PRs referencing actions nobody else can use. We require the repo to
    be genuinely public before treating it as a hardened equivalent.
    """
    r = _gh(f"repos/{candidate}", "--jq", "{private: .private, archived: .archived}", check=False)
    if r.returncode != 0:
        return False
    try:
        meta = json.loads(r.stdout)
    except (json.JSONDecodeError, TypeError):
        return False
    return meta.get("private") is False and not meta.get("archived", False)


_REPO_INDEX = None  # lowercased repo name -> actual repo name (public, non-archived)


def _public_repo_index():
    """
    Build (once) an index of every PUBLIC, non-archived chainguard-actions repo.

    Returns {lowercased_name: actual_name}, or None if the org listing could not
    be fetched (callers then fall back to per-candidate lookups). Matching against
    this index — rather than guessing exact names — is what makes mirror lookup
    resilient to naming variations (case differences, subpaths) so a public mirror
    isn't reported as "no equivalent" just because our guess didn't match exactly.
    """
    global _REPO_INDEX
    if _REPO_INDEX is not None:
        return _REPO_INDEX or None
    r = _gh("--paginate", "orgs/chainguard-actions/repos?per_page=100",
            "--jq", ".[] | select(.archived==false and .private==false) | .name",
            check=False)
    if r.returncode != 0 or not r.stdout.strip():
        _REPO_INDEX = {}          # cache the failure; signal "unavailable"
        return None
    _REPO_INDEX = {n.strip().lower(): n.strip() for n in r.stdout.splitlines() if n.strip()}
    return _REPO_INDEX


def _fetch_tags(cg_repo):
    r = _gh(f"repos/{cg_repo}/tags", "--paginate", "--jq", ".[].name", check=False)
    if r.returncode == 0 and r.stdout.strip():
        return sorted(
            [t.strip() for t in r.stdout.splitlines() if t.strip()],
            key=_tag_sort_key, reverse=True,
        )
    return []


def _candidate_names(action_name):
    """Mirror-name candidates for an upstream action, most specific first.

    `owner/repo` -> ["owner-repo", "repo"]; a subpath (`owner/repo/sub`) resolves
    on the repo, dropping the subpath.
    """
    parts = [p for p in action_name.split("/") if p]
    if len(parts) < 2:
        return []
    owner, repo = parts[0], parts[1]
    return [f"{owner}-{repo}", repo]


def get_hardened_tags(action_name):
    """
    Look up the Chainguard hardened equivalent of action_name.

    Resolves the mirror name (`{owner}-{repo}`, then `{repo}`) against an index of
    all PUBLIC, non-archived chainguard-actions repos — case-insensitively and with
    subpath handling — so public mirrors are found even when the exact name differs
    from a naive guess. Private / in-development repos are never in the index, so
    they are never recommended. Falls back to a direct per-candidate check if the
    org index can't be fetched.

    FUTURE: replace with chainctl actions catalog list lookup
    (see module docstring piece 1).
    """
    if "/" not in action_name:
        return None, []
    candidates = _candidate_names(action_name)

    index = _public_repo_index()
    if index is not None:
        for cand in candidates:
            real = index.get(cand.lower())
            if real:
                tags = _fetch_tags(f"chainguard-actions/{real}")
                if tags:
                    return f"chainguard-actions/{real}", tags
        return None, []

    # Index unavailable (e.g. org listing failed): fall back to per-candidate checks.
    for cand in candidates:
        full = f"chainguard-actions/{cand}"
        if _is_public_action_repo(full):
            tags = _fetch_tags(full)
            if tags:
                return full, tags
    return None, []


def _tag_sort_key(tag):
    m = re.match(r'^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?', tag)
    return (int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)) if m else (0, 0, 0)


def _parse_major(ref):
    if not ref:
        return None
    # A bare commit SHA must not be read as a version — its leading hex digits
    # ("74a5d1...") would otherwise be mistaken for a major like v74.
    if _SHA_RE.match(ref):
        return None
    m = re.match(r'^v?(\d+)$|^v?(\d+)\.', ref)
    if not m:
        return None
    return int(m.group(1) or m.group(2))


def resolve_version(cg_repo, tags, upstream_ref, strategy):
    """
    Pick the best hardened tag for upstream_ref per version strategy.
    Returns (hardened_available, hardened_ref, hardened_note).
      hardened_available: True | "version-gap" | False
    """
    if not tags:
        return False, None, None

    upstream_major = _parse_major(upstream_ref)

    if strategy == "latest" or upstream_major is None:
        chosen = tags[0]
        chosen_major = _parse_major(chosen)
        if upstream_major is not None and chosen_major != upstream_major:
            return (
                "version-gap",
                f"{cg_repo}@{chosen}",
                f"upstream pins v{upstream_major}, nearest hardened tag is {chosen} "
                f"— major version jump, review with: inputs before merging",
            )
        return True, f"{cg_repo}@{chosen}", None

    same_major = sorted(
        [t for t in tags if _parse_major(t) == upstream_major],
        key=_tag_sort_key, reverse=True,
    )
    if same_major:
        return True, f"{cg_repo}@{same_major[0]}", None

    chosen = tags[0]
    return (
        "version-gap",
        f"{cg_repo}@{chosen}",
        f"upstream pins v{upstream_major}, no hardened v{upstream_major}.x found "
        f"— nearest available is {chosen}",
    )


# ---------------------------------------------------------------------------
# Actions list parsing (list mode)
# ---------------------------------------------------------------------------

def parse_actions_list(content):
    """
    Parse a list of actions from text. Returns [(name, ref), ...].

    Accepts:
      - One per line: owner/repo@ref  or  owner/repo  (no version)
      - CSV: owner/repo, ref  or  name, version  (header row auto-skipped)
      - # comment lines and blank lines are ignored
    """
    lines = [l.strip() for l in content.splitlines()]
    lines = [l for l in lines if l and not l.startswith("#")]
    if not lines:
        return []

    first_fields = [f.strip() for f in lines[0].split(",")]
    if len(first_fields) >= 2 and "/" not in first_fields[0]:
        lines = lines[1:]

    results = []
    for line in lines:
        if "," in line:
            parts = [p.strip() for p in line.split(",", 1)]
            name_part, ref = parts[0], (parts[1] if len(parts) > 1 else "")
        else:
            name_part, ref = line, ""

        if "@" in name_part:
            name_part, ref = name_part.split("@", 1)

        name_part = name_part.strip()
        ref = ref.strip().lstrip("@")

        if "/" in name_part:
            results.append((name_part, ref))
        else:
            print(f"warning: skipping malformed line: {line!r}", file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# Inventory emission
# ---------------------------------------------------------------------------

def _emit_inventory(raw, *, scope, org_label, generated_by, strategy, resolve_action):
    """Resolve each discovered action against the catalog and print inventory.json.

    Resolution is PER DISTINCT VERSION: the same action used at two majors (e.g.
    actions/checkout@v4 and @v6) can resolve differently — one a clean swap, the
    other a version gap. Each occurrence carries its own hardened_* fields, and the
    action-level fields summarise them (with "mixed" when occurrences disagree), so
    a gap usage is never masked by an available one.
    """
    if raw:
        print("Resolving Chainguard hardened equivalents...", file=sys.stderr)
    actions = []
    for name, data in sorted(raw.items()):
        occ = data["occurrences"]

        # Resolve each occurrence by its own effective version (comment version
        # when SHA-pinned). Cache by version so we don't re-resolve duplicates.
        ver_cache = {}
        for o in occ:
            v = o.get("version") or o.get("ref") or None
            if v not in ver_cache:
                ver_cache[v] = resolve_action(name, v)
            ha, hr, hn = ver_cache[v]
            o["hardened_available"] = ha
            o["hardened_ref"] = hr
            o["hardened_note"] = hn

        # Aggregate to action level.
        statuses = {o["hardened_available"] for o in occ}
        if len(statuses) == 1:
            agg_status = next(iter(statuses))
            agg_ref = occ[0]["hardened_ref"]
            agg_note = occ[0]["hardened_note"]
        else:
            agg_status = "mixed"
            agg_ref = None
            # One line per distinct version, e.g. "v4 → version-gap; v6 → available".
            seen, parts = set(), []
            for o in occ:
                v = o.get("version") or o.get("ref") or "(unspecified)"
                if v in seen:
                    continue
                seen.add(v)
                parts.append(f"{v} → {o['hardened_available']}")
            agg_note = "varies by version: " + "; ".join(parts)

        actions.append({
            "name": name,
            "occurrences": occ,
            "hardened_available": agg_status,
            "hardened_ref": agg_ref,
            "hardened_note": agg_note,
        })

    print(json.dumps({
        "scope": scope,
        "org": org_label,
        "generated_by": generated_by,
        "version_strategy": strategy,
        "actions": actions,
    }, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("repos", nargs="*", metavar="owner/repo",
                    help="Repos to scan. Omit when using --org, --local, or --actions-list.")
    ap.add_argument("--org", help="GitHub org — scans all repos.")
    ap.add_argument("--local", metavar="PATH", nargs="?", const=".",
                    help="Scan a local checkout (default: current directory). "
                         "No GitHub access needed to read workflows; catalog lookups still use gh.")
    ap.add_argument("--actions-list", metavar="FILE",
                    help="File of actions to resolve (one per line or CSV). Use - for stdin.")
    ap.add_argument(
        "--version-strategy",
        choices=["same-major", "latest"],
        default="same-major",
        help="same-major (default): prefer latest hardened tag within the same major. "
             "latest: always use the newest hardened tag (may involve a major jump).",
    )
    args = ap.parse_args(argv)
    strategy = args.version_strategy

    catalog_cache = {}

    def resolve_action(name, upstream_ref):
        # Already a Chainguard hardened action — no swap to recommend.
        if name.startswith("chainguard-actions/"):
            return "already-hardened", None, "Already a Chainguard hardened action — no change needed"
        if name not in catalog_cache:
            catalog_cache[name] = get_hardened_tags(name)
        cg_repo, tags = catalog_cache[name]
        if cg_repo is None:
            return False, None, None
        return resolve_version(cg_repo, tags, upstream_ref, strategy)

    # --- LIST MODE ---
    if args.actions_list:
        if args.actions_list == "-":
            content = sys.stdin.read()
        else:
            with open(args.actions_list, "r", encoding="utf-8") as f:
                content = f.read()
        action_list = parse_actions_list(content)
        if not action_list:
            print("error: no valid actions found in input", file=sys.stderr)
            return 1

        print(f"Resolving {len(action_list)} action(s) from list...", file=sys.stderr)
        actions = []
        for name, ref in action_list:
            ha, hr, hn = resolve_action(name, ref or None)
            occ = ([{"repo": "(input list)", "workflow": "(input list)",
                     "ref": ref, "version": ref, "line": None,
                     "hardened_available": ha, "hardened_ref": hr, "hardened_note": hn}]
                   if ref else [])
            actions.append({
                "name": name,
                "occurrences": occ,
                "hardened_available": ha,
                "hardened_ref": hr,
                "hardened_note": hn,
            })

        print(json.dumps({
            "scope": "repo",
            "org": None,
            "generated_by": "actions-list",
            "version_strategy": strategy,
            "actions": actions,
        }, indent=2))
        return 0

    # --- LOCAL MODE: scan a checkout on disk ---
    if args.local is not None:
        import os
        root = os.path.abspath(args.local)
        repo_label = os.path.basename(root.rstrip(os.sep)) or root
        print(f"Scanning local checkout {root} ...", file=sys.stderr)
        raw = defaultdict(lambda: {"occurrences": []})
        for wf_path, name, ref, version, line in scan_local_dir(root):
            raw[name]["occurrences"].append(
                {"repo": repo_label, "workflow": wf_path, "ref": ref,
                 "version": version, "line": line}
            )
        if not raw:
            print(
                f"warning: no GitHub Actions found under {root}/.github/workflows/",
                file=sys.stderr,
            )
        return _emit_inventory(raw, scope="repo", org_label=None,
                               generated_by="local-scan", strategy=strategy,
                               resolve_action=resolve_action)

    # --- PRIMARY MODE: repo/org scanning ---
    repos = list(args.repos)
    if args.org:
        print(f"Listing repos in {args.org}...", file=sys.stderr)
        repos += list_org_repos(args.org)
    if not repos:
        ap.error("Provide an owner/repo, --org, --local, or --actions-list.")

    org_label = args.org or (repos[0].split("/")[0] if len(repos) == 1 else None)

    print(f"Scanning {len(repos)} repo(s) for GitHub Actions usage...", file=sys.stderr)
    raw = defaultdict(lambda: {"occurrences": []})
    for repo in repos:
        print(f"  {repo}", file=sys.stderr)
        for wf_path, name, ref, version, line in scan_repo(repo):
            raw[name]["occurrences"].append(
                {"repo": repo, "workflow": wf_path, "ref": ref,
                 "version": version, "line": line}
            )

    return _emit_inventory(raw, scope=("org" if args.org else "repo"),
                           org_label=org_label, generated_by="gh-api-scan",
                           strategy=strategy, resolve_action=resolve_action)

if __name__ == "__main__":
    raise SystemExit(main())
