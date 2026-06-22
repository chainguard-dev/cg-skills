#!/usr/bin/env python3
"""
summarize_inventory.py — render migration reports from inventory.json.

Report levels:
  --level summary       Org-wide view: every action, versions in use, repo/workflow/
                        usage counts, and hardened coverage. Default opening report.
  --level by-repo       Per-repository breakdown of hardenable actions.
  --level by-workflow   Per workflow file: each action, line number, and exact
                        hardened target. Review surface before generating edits.

Emit a mapping file for rewrite_workflows.py:
  --emit-mapping mapping.json               # confirmed-available actions only
  --emit-mapping mapping.json --include-gaps  # also include version-gap actions

inventory.json schema (produced by discover.py or scan_workflows.py):
  {
    "org": "myorg", "generated_by": "gh-api-scan", "version_strategy": "same-major",
    "actions": [
      {
        "name": "actions/checkout",
        "occurrences": [{"repo": "...", "workflow": "...", "ref": "v4", "line": 9}],
        "hardened_available": true | "version-gap" | "already-hardened" | false | null,
        "hardened_ref": "chainguard-actions/actions-checkout@v6.0.2" | null,
        "hardened_note": "explanation of version gap" | null
      }
    ]
  }
"""
import argparse
import json
import sys
from collections import defaultdict


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _md_table(headers, rows, aligns=None):
    """Render a fixed-width Markdown table.

    Padding the cells keeps the columns aligned when the output is shown as
    monospace text (e.g. inside a code fence), and is still valid Markdown that
    renders as a normal table. Returns a list of lines.
    """
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    cells = [[str(c) for c in row] for row in rows]
    widths = [len(str(headers[i])) for i in range(cols)]
    for row in cells:
        for i in range(cols):
            widths[i] = max(widths[i], len(row[i]))

    def fmt(row):
        out = []
        for i, c in enumerate(row):
            pad = widths[i] - len(c)
            out.append((" " * pad + c) if aligns[i] == "r" else (c + " " * pad))
        return "| " + " | ".join(out) + " |"

    sep = []
    for i in range(cols):
        dashes = "-" * max(3, widths[i])
        sep.append(dashes[:-1] + ":" if aligns[i] == "r" else dashes)
    return [fmt(headers), "| " + " | ".join(sep) + " |"] + [fmt(r) for r in cells]


def cov_label(ha):
    """Label for a hardened_available value (accepts the value, not the dict)."""
    if isinstance(ha, dict):  # tolerate being passed an action/occurrence
        ha = ha.get("hardened_available")
    if ha is True:
        return "✅ available"
    if ha == "already-hardened":
        return "🛡️ already hardened"
    if ha == "mixed":
        return "◐ mixed (per version)"
    if ha == "version-gap":
        return "⚠️ version gap"
    if ha is False:
        return "❌ no equivalent"
    return "? not checked"


def _versions_label(a, max_show=3):
    """Distinct versions in use, e.g. 'v4' or 'v3, v4' or 'v2, v3 +1 more'.
    Prefers the human version (from a trailing comment) over a bare SHA ref."""
    refs = sorted({(o.get("version") or o.get("ref")) for o in a["occurrences"]
                   if o.get("version") or o.get("ref")})
    if not refs:
        return "(unspecified)"
    if len(refs) <= max_show:
        return ", ".join(refs)
    shown = ", ".join(refs[:max_show])
    return f"{shown} +{len(refs) - max_show} more"


def summary(inv):
    actions = inv["actions"]
    org = inv.get("org") or "(org)"
    strategy = inv.get("version_strategy", "same-major")
    total_usages = sum(len(a["occurrences"]) for a in actions)
    all_repos = {o["repo"] for a in actions for o in a["occurrences"]}
    all_workflows = {(o["repo"], o["workflow"]) for a in actions for o in a["occurrences"]}
    avail = [a for a in actions if a.get("hardened_available") is True]
    already = [a for a in actions if a.get("hardened_available") == "already-hardened"]
    mixed = [a for a in actions if a.get("hardened_available") == "mixed"]
    gaps = [a for a in actions if a.get("hardened_available") == "version-gap"]
    not_avail = [a for a in actions if a.get("hardened_available") is False]
    unknown = [a for a in actions if a.get("hardened_available") is None]
    coverable_usages = sum(len(a["occurrences"]) for a in avail)

    # Usage-level tally (more honest than action-level when an action is "mixed").
    occ_status = [o.get("hardened_available") for a in actions for o in a["occurrences"]]
    u_avail = sum(1 for s in occ_status if s is True)
    u_gap = sum(1 for s in occ_status if s == "version-gap")

    lines = [f"# Chainguard Actions migration — {org}", ""]
    lines.append(f"- Distinct actions in use: **{len(actions)}**")
    lines.append(f"- Total usages: **{total_usages}** across **{len(all_repos)}** repos, **{len(all_workflows)}** workflows")
    lines.append(f"- ✅ Hardened equivalent available: **{len(avail)}** actions ({coverable_usages} usages)")
    if already:
        already_usages = sum(len(a["occurrences"]) for a in already)
        lines.append(f"- 🛡️ Already hardened (no change needed): **{len(already)}** actions ({already_usages} usages)")
    if mixed:
        lines.append(f"- ◐ Mixed (status varies by version in use): **{len(mixed)}** actions")
    if gaps:
        gap_usages = sum(len(a["occurrences"]) for a in gaps)
        lines.append(f"- ⚠️  Version gap (major jump required): **{len(gaps)}** actions ({gap_usages} usages)")
    if not_avail:
        lines.append(f"- ❌ No hardened equivalent: **{len(not_avail)}** actions")
    if unknown:
        lines.append(f"- ?  Not yet checked: **{len(unknown)}** actions")
    lines.append(f"- By usage: **{u_avail}** swappable now, **{u_gap}** need a version review")
    # Sanity check: the status buckets must sum to the distinct-action total.
    bucket_total = len(avail) + len(already) + len(mixed) + len(gaps) + len(not_avail) + len(unknown)
    if bucket_total != len(actions):
        lines.append(f"- ⚠️ internal: status buckets ({bucket_total}) != distinct actions ({len(actions)})")
    lines.append(f"- Version strategy: **{strategy}**")
    lines.append("")
    rows = []
    for a in sorted(actions, key=lambda x: -len(x["occurrences"])):
        repos = len({o["repo"] for o in a["occurrences"]})
        wfs = len({(o["repo"], o["workflow"]) for o in a["occurrences"]})
        usages = len(a["occurrences"])
        rows.append([f"`{a['name']}`", _versions_label(a), repos, wfs, usages, cov_label(a)])
    lines += _md_table(
        ["Action", "Versions in use", "Repos", "Workflows", "Usages", "Hardened"],
        rows, aligns=["l", "l", "r", "r", "r", "l"],
    )
    return "\n".join(lines)


def by_repo(inv):
    repo_map = defaultdict(lambda: defaultdict(int))
    meta = {a["name"]: a for a in inv["actions"]}
    for a in inv["actions"]:
        for o in a["occurrences"]:
            repo_map[o["repo"]][a["name"]] += 1

    # Per-occurrence usage status, so mixed actions count correctly per repo.
    repo_usage = defaultdict(lambda: {"avail": 0, "gap": 0})
    for a in inv["actions"]:
        for o in a["occurrences"]:
            s = o.get("hardened_available")
            if s is True:
                repo_usage[o["repo"]]["avail"] += 1
            elif s == "version-gap":
                repo_usage[o["repo"]]["gap"] += 1

    out = [f"# Migration detail by repo — {inv.get('org') or '(org)'}", ""]
    for repo in sorted(repo_map):
        acts = repo_map[repo]
        hardenable = repo_usage[repo]["avail"]
        gap = repo_usage[repo]["gap"]
        total = sum(acts.values())
        parts = [f"{hardenable}/{total} usages hardenable"]
        if gap:
            parts.append(f"{gap} need version review")
        out.append(f"## {repo}  ({', '.join(parts)})")
        out.append("")
        rows = [[f"`{n}`", _versions_label(meta[n]), acts[n], cov_label(meta[n])]
                for n in sorted(acts, key=lambda x: -acts[x])]
        out += _md_table(["Action", "Versions in use", "Usages", "Hardened"],
                         rows, aligns=["l", "l", "r", "l"])
        out.append("")
    return "\n".join(out)


def by_workflow(inv):
    # Per-OCCURRENCE resolution — each line shows its own status/target, so a
    # gap usage and an available usage of the same action read accurately.
    tree = defaultdict(lambda: defaultdict(list))
    for a in inv["actions"]:
        for o in a["occurrences"]:
            tree[o["repo"]][o["workflow"]].append((o.get("line"), a["name"], o))
    out = [f"# Migration detail by workflow — {inv.get('org') or '(org)'}", ""]
    for repo in sorted(tree):
        out.append(f"## {repo}")
        for wf in sorted(tree[repo]):
            out.append(f"### `{wf}`")
            out.append("")
            wf_notes = []
            rows = []
            for line, name, o in sorted(tree[repo][wf], key=lambda x: (x[0] or 0)):
                ref = o.get("version") or o.get("ref")
                cur = name + (f"@{ref}" if ref else "")
                ha = o.get("hardened_available")
                href = o.get("hardened_ref")
                note = o.get("hardened_note")
                if ha is True and href:
                    tgt = href
                elif ha == "version-gap" and href:
                    tgt = href + " ⚠️"
                elif ha == "already-hardened":
                    tgt = "🛡️ already hardened"
                elif ha is False:
                    tgt = "❌ no equivalent"
                else:
                    tgt = cov_label(ha)
                rows.append([line or "", f"`{cur}`", tgt])
                if ha == "version-gap" and note:
                    wf_notes.append((cur, note))
            out += _md_table(["Line", "Current", "→ Hardened"], rows,
                             aligns=["r", "l", "l"])
            if wf_notes:
                out.append("")
                for cur, note in wf_notes:
                    out.append(f"> ⚠️ **`{cur}`**: {note}")
            out.append("")
    return "\n".join(out)


def emit_mapping(inv, path, include_gaps=False):
    """Emit a name@version -> hardened_ref mapping from PER-OCCURRENCE resolution.

    Keying by version (not just name) is what lets a mixed-version action be
    handled correctly: the available version(s) are swapped while a gap version
    is left alone (unless --include-gaps). rewrite_workflows.py matches the
    line's effective version, falling back to a bare-name key.
    """
    mapping = {}
    for a in inv["actions"]:
        for o in a["occurrences"]:
            ha = o.get("hardened_available")
            href = o.get("hardened_ref")
            if not href:
                continue
            include = (ha is True) or (include_gaps and ha == "version-gap")
            if not include:
                continue
            ver = o.get("version") or o.get("ref")
            key = f'{a["name"]}@{ver}' if ver else a["name"]
            mapping[key] = href
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)
    return mapping


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inventory")
    ap.add_argument("--level", choices=["summary", "by-repo", "by-workflow"],
                    default="summary")
    ap.add_argument("--emit-mapping", metavar="FILE",
                    help="Write name->hardened_ref mapping JSON for rewrite_workflows.py")
    ap.add_argument("--include-gaps", action="store_true",
                    help="Include version-gap actions in --emit-mapping output")
    args = ap.parse_args(argv)

    inv = load(args.inventory)
    if args.emit_mapping:
        m = emit_mapping(inv, args.emit_mapping, include_gaps=args.include_gaps)
        gap_count = sum(1 for a in inv["actions"] if a.get("hardened_available") == "version-gap")
        note = f" (+ {gap_count} version-gap entries)" if args.include_gaps and gap_count else ""
        print(f"Wrote {len(m)} mapping entries to {args.emit_mapping}{note}", file=sys.stderr)

    if args.level == "summary":
        print(summary(inv))
    elif args.level == "by-repo":
        print(by_repo(inv))
    else:
        print(by_workflow(inv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
