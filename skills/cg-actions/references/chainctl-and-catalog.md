# GitHub API reference + future chainctl notes

How `discover.py` uses the GitHub API, and where chainctl plugs back in when ready.

---

## 1. Discovery via GitHub API

All calls go through `gh api`.

### List repos in an org
```bash
gh repo list <org> --limit 500 --json nameWithOwner --jq '.[].nameWithOwner'
```

### List workflow files in a repo
```bash
gh api repos/<owner>/<repo>/contents/.github/workflows \
  --jq '[.[] | select(.type=="file" and (.name | test("\\.ya?ml$"))) | .path]'
```
Returns `[]` or 404 if the repo has no workflows — handle both.

### Fetch a workflow file
```bash
gh api repos/<owner>/<repo>/contents/.github/workflows/<file> --jq '.content'
```
Content is base64-encoded with embedded newlines. Decode:
```python
base64.b64decode(raw).decode("utf-8", errors="replace")
```

---

## 2. Hardened catalog resolution

The `chainguard-actions` GitHub org is the source of truth. Naming convention:
`chainguard-actions/{upstream-owner}-{upstream-repo}`. Fallback: `chainguard-actions/{upstream-repo}`.

### Check if a hardened equivalent exists
```bash
gh api repos/chainguard-actions/<owner>-<repo>   # primary
gh api repos/chainguard-actions/<repo>            # fallback
```
404 on both → `hardened_available: false`.

### Get available tags
```bash
gh api repos/chainguard-actions/<name>/tags --paginate --jq '.[].name'
```
`discover.py` sorts these by semver descending, then applies the version strategy.

### Version strategy logic
- **`same-major`**: filter tags to those matching the upstream major; pick highest.
  If none match, fall back to overall latest and mark `version-gap`.
- **`latest`**: pick the highest overall tag. Still mark `version-gap` if major differs.

---

## 3. Allowlist management

Read current patterns before writing — never overwrite without merging:
```bash
gh api repos/<owner>/<repo>/actions/permissions/selected-actions
```

Add `chainguard-actions/*` while preserving existing entries:
```bash
gh api repos/<owner>/<repo>/actions/permissions/selected-actions \
  --method PUT \
  --field "github_owned_allowed=false" \
  --field "verified_allowed=false" \
  --field "patterns_allowed[]=chainguard-actions/*" \
  --field "patterns_allowed[]=<each existing pattern>"
```

Always show the before/after diff and confirm with the user before executing.

---

## 4. Issue and PR body templates

### Tracking issue
```markdown
## Harden CI with Chainguard Actions

Migrating GitHub Actions to hardened `chainguard-actions/*` equivalents.

**Scope:** {N} actions, {M} usages across {R} repos.
**Ready to swap:** {K} actions ({U} usages).
**Version gaps (need review):** {G} actions.

### Per-repo PRs
- [ ] owner/repo1 — {n} swaps
- [ ] owner/repo2 — {n} swaps

Each PR changes only `uses:` references. Inputs unchanged; CI must pass before merge.
```

### PR body
```markdown
## Harden GitHub Actions with Chainguard

| Workflow | Current | → Hardened |
|---|---|---|
| .github/workflows/ci.yml | actions/checkout@v4 | chainguard-actions/actions-checkout@v6.0.2 |

**Reviewer notes**
- Only `uses:` references changed — no `with:` inputs, permissions, or formatting touched.
- [If version gaps] ⚠️ Some swaps involve a major version jump — review `with:` inputs.
- `chainguard-actions/*` must be in Settings → Actions → General → Allow specified actions.
```

---

## 5. Future chainctl integration

When `chainctl actions discover` returns per-action catalog annotations, replace
`discover.py` with a wrapper that:

1. Runs `chainctl actions discover <org> -o json` (or loops per repo)
2. Normalizes to the same `inventory.json` schema — same field names, same types
3. Passes the result to the same downstream scripts unchanged

`discover.py` sets `generated_by: "gh-api-scan"`. The chainctl wrapper would set
`generated_by: "chainctl actions discover"`. Nothing downstream reads this field.

Key fields to map from chainctl output → inventory schema:
- action name → `name`
- usage locations → `occurrences[]` with `repo`, `workflow`, `line`, `ref`
- hardened equivalent ref → `hardened_ref`
- whether one exists → `hardened_available` (true / false / "version-gap")
