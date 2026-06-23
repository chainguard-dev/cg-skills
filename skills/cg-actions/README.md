# cg-actions

A Claude Code skill for auditing GitHub Actions usage and migrating to
[Chainguard hardened actions](https://github.com/chainguard-actions).

## Install

The recommended way to install is the **hardened** build, distributed through
[Chainguard Agent Skills](https://www.chainguard.dev/):

```
chainctl skills install skills.cgr.dev/chainguard/chainguard-dev/cg-actions:latest
```

This pulls the skill from the Chainguard registry (`skills.cgr.dev`) — built,
signed, and continuously maintained the same way as Chainguard's other hardened
artifacts. Pin a specific version instead of `:latest` if you want reproducible
installs.

---

**Requires an environment that can run scripts and call the GitHub API** — i.e.
Claude Code (or another agent with a shell tool) plus `gh` authenticated
(`gh auth login`). It does **not** work in a plain claude.ai chat with no shell;
the skill checks for this and stops rather than guessing.

**Version / updates.** The installed version is in [VERSION](VERSION). At startup
the skill runs `scripts/check_version.py`, which compares it to the latest
published in [chainguard-dev/cg-skills](https://github.com/chainguard-dev/cg-skills)
(`skills/cg-actions/VERSION`) and suggests updating if you're behind. To update,
download the latest from <https://github.com/chainguard-dev/cg-skills>.
Maintainers: bump `VERSION` whenever you change the skill so installs can detect it.

---

## Two commands

```
/cg-actions audit  [target] [options]   — discover, report, export
/cg-actions migrate [target] [options]  — rewrite, PRs, allowlist
```

- **`audit` is read-only** — it discovers and reports, then stops. It never opens
  PRs/issues or changes settings, and won't drift into doing so.
- **`migrate` is the only command that writes** — and it confirms before every
  GitHub write unless `--yes`.

**Default target:** with no target, both commands operate on the **current
directory's repo** (detected via `gh repo view`, or scanned locally with `--local`).

Both work in two modes:
- **Interactive** (type just the target): guided with follow-up questions (migrate only)
- **Direct** (add flags): executes specified steps, still confirms before GitHub writes

---

## `audit`

```
/cg-actions audit [TARGET] [OPTIONS]

TARGET (defaults to the current directory's repo if omitted):
  owner/repo              Single GitHub repo
  --org ORGNAME           All repos in the org
  --local [PATH]          Local checkout (default: current directory)
  --actions-list FILE|-   Resolve a pasted/file list of actions (no repo access needed)

OPTIONS:
  --level summary|by-repo|by-workflow   (default: summary)
  --version-strategy same-major|latest  (default: same-major)
  --export excel                         Also produce an .xlsx report
  --export html                          Also produce an interactive HTML report (auto-opens)
  --include-gaps                         Highlight version gaps prominently
```

**Examples:**
```
/cg-actions audit owner/repo
/cg-actions audit --org myorg --export excel
/cg-actions audit --org myorg --export html
/cg-actions audit --org myorg --level by-workflow
/cg-actions audit owner/repo --version-strategy latest
/cg-actions audit --actions-list -     ← paste a list of actions
```

**Actions list formats** (auto-detected):
```
# one per line
actions/checkout@v4
sigstore/cosign-installer@v3

# CSV (header auto-skipped)
name,version
actions/checkout,v4
```

**Status values:**

| | Status | Meaning |
|---|---|---|
| ✅ | available | Public hardened equivalent at same major version — drop-in swap |
| 🛡️ | already hardened | Already a `chainguard-actions/*` action — no change needed |
| ◐ | mixed | Used at multiple versions that resolve differently (some available, some gap) |
| ⚠️ | version gap | Hardened action exists but only at a different major version |
| ❌ | no equivalent | No public hardened equivalent in the catalog |
| ? | not checked | Not resolved — scripts didn't run (never guessed) |

Resolution is **per version**: `actions/checkout@v4` (gap) and `@v6` (available)
resolve separately, even within one action. An action used at versions that
resolve differently is **◐ mixed**; the per-workflow view and the rewrite operate
per occurrence, so a gap usage is never silently swapped as a clean one.

Only **public, non-archived** `chainguard-actions/*` repos count as equivalents,
so private/in-development repos are never recommended.

**Example summary output:**
```
# Chainguard Actions migration — myorg

- Distinct actions in use: 7
- Total usages: 50 across 8 repos, 23 workflows
- ✅ Hardened equivalent available: 3 actions (32 usages)
- 🛡️ Already hardened (no change needed): 1 action (3 usages)
- ⚠️  Version gap (major jump required): 1 action (3 usages)
- ❌ No hardened equivalent: 2 actions (12 usages)
- Version strategy: same-major

| Action                            | Versions in use | Repos | Workflows | Usages | Hardened           |
|-----------------------------------|-----------------|------:|----------:|-------:|--------------------|
| actions/checkout                  | v3, v4          |     8 |        18 |     21 | ✅ available        |
| docker/login-action               | v4.2.0          |     6 |         8 |      9 | ✅ available        |
| sigstore/cosign-installer         | v3              |     4 |         5 |      5 | ✅ available        |
| chainguard-actions/setup-crane    | v0.6            |     3 |         3 |      3 | 🛡️ already hardened |
| aws-actions/configure-aws-creds   | v1              |     2 |         3 |      3 | ⚠️ version gap     |
| hashicorp/setup-terraform         | v2              |     2 |         2 |      6 | ❌ no equivalent    |
| renovatebot/github-action         | v46             |     2 |         2 |      6 | ❌ no equivalent    |
```

Versions shown are the human version from a trailing `# vX.Y.Z` comment when the
`uses:` ref is a bare SHA, so SHA-pinned workflows still read cleanly. All counts
come straight from the script — never hand-tallied.

**By-workflow detail** (`--level by-workflow`):
```
## myorg/api
### `.github/workflows/ci.yml`

| Line | Current                              | → Hardened                                           |
|-----:|--------------------------------------|------------------------------------------------------|
|    9 | actions/checkout@v4                  | chainguard-actions/actions-checkout@v6.0.2           |
|   23 | docker/build-push-action@v5          | chainguard-actions/docker-build-push-action@v6.1.0   |
|   31 | aws-actions/configure-aws-creds@v1   | chainguard-actions/aws-configure-aws-creds@v4.0.2 ⚠️ |
|   40 | hashicorp/setup-terraform@v2         | ❌ no equivalent                                     |

> ⚠️ **`aws-actions/configure-aws-creds`**: upstream pins v1, no hardened v1.x
> found — nearest available is v4.0.2
```

**Excel export** (`--export excel`): three-sheet workbook — Summary, Actions
(filterable), Usages (one row per occurrence). Best for large orgs or sharing
outside Claude. Requires `pip install openpyxl`.

**HTML export** (`--export html`): self-contained interactive HTML report with
filter chips by status, copy-to-clipboard for hardened refs, stat cards, and
per-workflow line-by-line breakdown. Auto-opens in the default browser. No
extra dependencies. Good for sharing with teams or embedding in internal docs.

---

## `migrate`

```
/cg-actions migrate [TARGET] [OPTIONS]

TARGET (defaults to the current directory's repo if omitted):
  owner/repo              Single repo
  --org ORGNAME           All repos in the org
  --local [PATH]          Local checkout (default: current directory)

OPTIONS:
  --dry-run               Generate diffs only, no GitHub writes
  --pr                    Create a PR per repo
  --issue                 Create a tracking issue
  --allowlist             Add chainguard-actions/* to each repo's Actions allowlist (if enforced)
  --remove-replaced       Also remove allowlist entries for replaced upstream actions
  --include-gaps          Include version-gap actions in the rewrite
  --version-strategy same-major|latest
  --yes                   Skip confirmation prompts (power-user mode)
```

**Examples:**
```
/cg-actions migrate owner/repo
/cg-actions migrate owner/repo --dry-run
/cg-actions migrate owner/repo --pr --allowlist
/cg-actions migrate owner/repo --pr --issue --allowlist --include-gaps
/cg-actions migrate --org myorg --pr --allowlist --yes
```

Without `--dry-run`, `--pr`, or `--issue`: shows what would change and asks what
to do. With flags: executes those steps. Confirms per repo before writes unless `--yes`.

**Allowlist behavior** (`--allowlist`): the skill checks the repo's Actions policy
first. If it's set to **allow all actions** (the common default), nothing needs to
change and no edit is made. If an **allowlist is enforced**, `chainguard-actions/*`
is merged into the existing patterns via the GitHub API (existing entries
preserved) — not punted to the UI. The UI is only suggested if `gh` can't make the
change.

**Before merging any PR:**
- For ⚠️ version-gap swaps: review `with:` inputs carefully
- CI must pass
- If the repo enforces an Actions allowlist, `chainguard-actions/*` must be in it
  (handled automatically with `--allowlist`)

---

## Interactive flow (general users)

`audit` reports and stops:
```
/cg-actions audit myorg
→ builds inventory, shows summary, then points you to `migrate`. No changes made.
```

`migrate` is where the decisions happen:
```
/cg-actions migrate myorg
→ asks four questions (deliverable, version strategy, version gaps, allowlist),
  then proceeds — confirming before each GitHub write.
```

---

## Version strategy

| Strategy | Behavior |
|---|---|
| `same-major` (default) | Latest hardened tag within same major version as upstream. Marks ⚠️ version gap if no same-major tag exists. |
| `latest` | Always newest hardened tag. Marks ⚠️ version gap when major differs from upstream. |

---

## Session examples

**Power user (no prompts):**
```
/cg-actions audit --org myorg --export excel
/cg-actions migrate --org myorg --pr --issue --allowlist --include-gaps --yes
```

**Guided (general user):**
```
/cg-actions audit myorg
→ summary shown, then a pointer to migrate. Read-only — nothing changes.

/cg-actions audit myorg --level by-workflow
→ exact lines and replacement refs

/cg-actions migrate myorg --dry-run
→ diffs shown for review

/cg-actions migrate myorg --pr --issue --allowlist --include-gaps
→ four questions answered, confirmed per repo, PRs + issue + allowlist updated
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
