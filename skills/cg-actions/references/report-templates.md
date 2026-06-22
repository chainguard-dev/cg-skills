# Report templates

`summarize_inventory.py` generates the three report tiers from `inventory.json`.
Lead with the summary; only produce deeper tiers when the user asks for them.

## Tier 1 — high-level summary (default opening)
`summarize_inventory.py inventory.json --level summary`

Opens with org-level counts (distinct actions, total usages, repos, how many
actions have a hardened equivalent and how many usages that covers, plus anything
still uncharted), then a table sorted by usage:

| Action | Usages | Repos | Hardened |
|---|---:|---:|---|

After showing it, offer the next tiers and the rewrite, e.g.:
"Want this broken out by repo, drilled into individual workflow files, or shall I
generate the updated workflow YAMLs you could commit?"

## Tier 2 — by repo
`summarize_inventory.py inventory.json --level by-repo`
Per repository: how many usages are hardenable, then the per-action table.

## Tier 3 — by workflow file
`summarize_inventory.py inventory.json --level by-workflow`
Per repo → per workflow file → each action with its line and the exact hardened
target ref. This is the review surface before generating rewrites.

## Tier 4 — updated workflow YAMLs
1. Emit the mapping: `summarize_inventory.py inventory.json --emit-mapping mapping.json`
2. Rewrite: `rewrite_workflows.py --mapping mapping.json --repo <repo> --out-dir rewritten/`
3. Present the unified diffs (`rewritten/**/*.diff`) for review. Each diff changes
   only `uses:` lines. State clearly that inputs/`with:` blocks are unchanged and
   need human review, and that CI should pass before merge.

## Issue body template (optional umbrella issue)

```markdown
## Harden CI with Chainguard Actions

Migrating GitHub Actions in this org to hardened `chainguard-actions/*` equivalents.

**Scope:** {N} distinct actions, {M} usages across {R} repos.
**Hardenable today:** {K} actions ({U} usages).

### Per-repo PRs
- [ ] acme/api — {n} swaps
- [ ] acme/web — {n} swaps

Each PR swaps only the `uses:` reference. Inputs are unchanged; CI must pass before
merge. Generated from `chainctl actions discover`.
```

## PR body template (per repo)

```markdown
## Harden GitHub Actions

Swaps third-party actions for Chainguard hardened equivalents (`chainguard-actions/*`).

| Workflow | Action | → Hardened |
|---|---|---|
| .github/workflows/ci.yml | actions/checkout@v4 | chainguard-actions/checkout@v4.2.2 |

**Reviewer notes**
- Only `uses:` references changed; no `with:`/inputs/permissions touched.
- Hardened actions are drop-in by design, but please confirm CI is green.
- To consume these, `chainguard-actions/*` must be allowlisted in repo →
  Settings → Actions → Allow specified actions.
```
