#!/usr/bin/env python3
"""Generate a self-contained, interactive HTML view of a cg-actions inventory.

Reads inventory.json (from discover.py) and writes a single HTML file styled
in the Guardener dashboard visual language: dark dev tool, status pills, dense
tables, sparing green accent. The file is self-contained (inline CSS + system
font fallbacks), opens in the default browser on macOS/Linux, and includes
client-side filter chips + copy-to-clipboard buttons for swap suggestions.

Usage:
    view.py inventory.json
    view.py inventory.json -o report.html
    view.py inventory.json --no-open
    cat inventory.json | view.py -
"""

import argparse
import html
import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


# ─── Embedded CSS ───────────────────────────────────────────────────────────────

CSS = """
:root {
  --bg-0: #0a0a0b; --bg-1: #111113; --bg-2: #161618; --bg-3: #1c1c1f; --bg-4: #232328;
  --border-1: #232328; --border-2: #2d2d33; --border-3: #3a3a42;
  --text-1: #f5f5f7; --text-2: #a8a8b3; --text-3: #6e6e78; --text-4: #48484f;
  --green: #1a8a5a; --green-bright: #22c478;
  --green-soft: rgba(34,196,120,.12); --green-border: rgba(34,196,120,.32);
  --amber: #d99a2b; --amber-soft: rgba(217,154,43,.12);
  --red: #e5484d; --red-soft: rgba(229,72,77,.12);
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, "JetBrains Mono", monospace;
  --r-sm: 4px; --r-md: 6px; --r-lg: 10px;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0; background: var(--bg-0); color: var(--text-1);
  font-family: var(--font-ui); font-size: 13px; line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; text-decoration: none; }
button { font-family: inherit; font-size: inherit; cursor: pointer; }

.topbar {
  display: flex; align-items: center; height: 48px; padding: 0 20px;
  border-bottom: 1px solid var(--border-1); background: var(--bg-0);
  position: sticky; top: 0; z-index: 10;
}
.topbar .brand {
  display: flex; align-items: center; gap: 8px;
  font-weight: 600; font-size: 14px; letter-spacing: -0.01em;
}
.topbar .scope {
  margin-left: 16px; padding: 4px 10px; border: 1px solid var(--border-2);
  border-radius: var(--r-sm); color: var(--text-2); font-size: 12px;
  font-family: var(--font-mono);
}
.topbar .right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.topbar .meta { font-size: 11px; color: var(--text-3); font-family: var(--font-mono); }

.page { max-width: 1280px; margin: 0 auto; padding: 28px 32px 80px; }
.page-header { margin-bottom: 24px; }
.page-header .breadcrumb {
  font-size: 11px; color: var(--text-3); margin-bottom: 6px;
  font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.08em;
}
.page-header h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; letter-spacing: -0.02em; }
.page-header .subtitle { color: var(--text-2); font-size: 13px; }
.page-header .subtitle strong { color: var(--text-1); font-weight: 500; }

.stat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin-bottom: 28px;
}
.stat-card {
  background: var(--bg-1); border: 1px solid var(--border-1);
  border-radius: var(--r-md); padding: 16px;
}
.stat-card .label {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--text-3); margin-bottom: 8px; font-weight: 500;
}
.stat-card .value {
  font-size: 30px; font-weight: 600; letter-spacing: -0.03em; line-height: 1;
  font-family: var(--font-mono);
}
.stat-card .delta { margin-top: 8px; font-size: 11px; color: var(--text-3); }
.stat-card.accent .value { color: var(--green-bright); }
.stat-card.teal   .value { color: #5fc8e0; }
.stat-card.purple .value { color: #b9a3ff; }
.stat-card.warn   .value { color: var(--amber); }
.stat-card.danger .value { color: var(--red); }
.stat-card.muted  .value { color: var(--text-2); }

.pill {
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 11px; font-weight: 500; padding: 2px 8px;
  border-radius: 999px; border: 1px solid;
  font-family: var(--font-ui); white-space: nowrap;
}
.pill .dot { width: 6px; height: 6px; border-radius: 50%; }
.pill.green { color: var(--green-bright); background: var(--green-soft); border-color: var(--green-border); }
.pill.green .dot { background: var(--green-bright); }
.pill.amber { color: var(--amber); background: var(--amber-soft); border-color: rgba(217,154,43,.3); }
.pill.amber .dot { background: var(--amber); }
.pill.red   { color: var(--red);   background: var(--red-soft);   border-color: rgba(229,72,77,.3); }
.pill.red .dot   { background: var(--red); }
.pill.gray  { color: var(--text-2); background: var(--bg-3); border-color: var(--border-2); }
.pill.gray .dot  { background: var(--text-3); }
.pill.teal  { color: #5fc8e0; background: rgba(58,166,194,.12); border-color: rgba(58,166,194,.32); }
.pill.teal .dot  { background: #5fc8e0; }
.pill.purple { color: #b9a3ff; background: rgba(155,125,255,.12); border-color: rgba(155,125,255,.32); }
.pill.purple .dot { background: #b9a3ff; }

.card {
  background: var(--bg-1); border: 1px solid var(--border-1);
  border-radius: var(--r-md); margin-bottom: 16px;
}
.card-header {
  padding: 12px 16px; border-bottom: 1px solid var(--border-1);
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
}
.card-header h3 {
  margin: 0; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-2);
}
.card-header .meta { font-size: 11px; color: var(--text-3); font-family: var(--font-mono); }
.card-header .path {
  font-family: var(--font-mono); font-size: 13px; color: var(--text-1);
  font-weight: 500; text-transform: none; letter-spacing: 0;
}

.bars { padding: 18px 16px 16px; display: flex; flex-direction: column; gap: 12px; }
.bar-row {
  display: grid; grid-template-columns: 160px 1fr 40px;
  align-items: center; gap: 12px; font-size: 12px;
}
.bar-row .label { color: var(--text-2); display: flex; align-items: center; gap: 6px; }
.bar-row .label .swatch { width: 8px; height: 8px; border-radius: 2px; }
.bar-row .track { height: 10px; background: var(--bg-3); border-radius: 3px; overflow: hidden; }
.bar-row .fill  { height: 100%; border-radius: 3px; }
.bar-row .num {
  text-align: right; font-family: var(--font-mono); color: var(--text-1);
  font-size: 11px; font-variant-numeric: tabular-nums;
}

.table { width: 100%; border-collapse: collapse; font-size: 12px; }
.table thead th {
  text-align: left; font-weight: 500; color: var(--text-3);
  padding: 8px 12px; border-bottom: 1px solid var(--border-1);
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  background: var(--bg-1);
}
.table thead th.num { text-align: right; }
.table tbody td {
  padding: 10px 12px; border-bottom: 1px solid var(--border-1); vertical-align: middle;
}
.table tbody tr:last-child td { border-bottom: none; }
.table tbody tr:hover { background: var(--bg-2); }
.table .mono  { font-family: var(--font-mono); font-size: 11.5px; }
.table .num   { text-align: right; font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
.table .muted { color: var(--text-3); }

.chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 16px 12px; }
.chip {
  padding: 5px 10px; border: 1px solid var(--border-2); border-radius: 999px;
  font-size: 11.5px; color: var(--text-2); background: transparent;
  display: inline-flex; align-items: center; gap: 5px;
}
.chip:hover { background: var(--bg-2); color: var(--text-1); }
.chip.active { background: var(--bg-3); color: var(--text-1); border-color: var(--border-3); }
.chip .count { color: var(--text-3); font-family: var(--font-mono); font-size: 10.5px; }

.code-inline {
  font-family: var(--font-mono); font-size: 11.5px;
  background: var(--bg-3); padding: 1px 6px; border-radius: 3px;
  color: var(--text-1); border: 1px solid var(--border-2);
}
.code-arrow { color: var(--text-3); margin: 0 6px; font-family: var(--font-mono); }

.copy-btn {
  background: transparent; border: 1px solid var(--border-2); color: var(--text-3);
  font-size: 10.5px; padding: 3px 8px; border-radius: var(--r-sm);
  font-family: var(--font-mono); transition: all 0.12s ease;
}
.copy-btn:hover { color: var(--text-1); border-color: var(--border-3); background: var(--bg-2); }
.copy-btn.copied { color: var(--green-bright); border-color: var(--green-border); }

.split { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; margin-bottom: 16px; }
@media (max-width: 900px) { .split, .stat-grid { grid-template-columns: 1fr; } }

.feed-row {
  padding: 12px 16px; border-bottom: 1px solid var(--border-1);
  display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: center;
}
.feed-row:last-child { border-bottom: none; }
.feed-row .repo { font-family: var(--font-mono); color: var(--text-1); font-size: 12px; }
.feed-row .detail { color: var(--text-3); font-size: 11px; margin-top: 2px; }

.section-title {
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--text-3); margin: 0 0 12px;
}

/* Filter chips toggle data-show-* on <body> */
/* Filter chips only govern the .filterable inventory table — NOT the per-workflow
   / per-repo detail rows (those carry data-status for colour but keep their own
   per-occurrence statuses, which would otherwise desync the chip counts). */
body[data-show-available="0"]       .filterable [data-status="available"]       { display: none; }
body[data-show-already-hardened="0"].filterable [data-status="already-hardened"]{ display: none; }
body[data-show-mixed="0"]           .filterable [data-status="mixed"]           { display: none; }
body[data-show-version-gap="0"]     .filterable [data-status="version-gap"]     { display: none; }
body[data-show-no-equivalent="0"]   .filterable [data-status="no-equivalent"]   { display: none; }
body[data-show-not-checked="0"]     .filterable [data-status="not-checked"]     { display: none; }

footer { margin-top: 48px; color: var(--text-4); font-size: 11px; text-align: center; }
"""


# ─── Embedded JS ────────────────────────────────────────────────────────────────

JS = """
(function() {
  const STATUSES = ['available', 'already-hardened', 'mixed', 'version-gap', 'no-equivalent', 'not-checked'];

  // Single-select "click to show": "All" (default) shows everything; clicking a
  // category shows only that one. Clicking the active category again resets to All.
  function select(filter) {
    document.querySelectorAll('.chip[data-filter]').forEach(c =>
      c.classList.toggle('active', c.dataset.filter === filter));
    STATUSES.forEach(s =>
      document.body.setAttribute('data-show-' + s, (filter === 'all' || filter === s) ? '1' : '0'));
  }

  document.querySelectorAll('.chip[data-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      const filter = chip.dataset.filter;
      // Re-clicking the currently-selected category returns to All.
      if (filter !== 'all' && chip.classList.contains('active')) {
        select('all');
      } else {
        select(filter);
      }
    });
  });

  document.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        const orig = btn.textContent;
        btn.classList.add('copied');
        btn.textContent = 'copied ✓';
        setTimeout(() => { btn.classList.remove('copied'); btn.textContent = orig; }, 1500);
      } catch (e) {}
    });
  });
})();
"""


# ─── Status helpers ──────────────────────────────────────────────────────────────

def _status_key(hardened_available):
    if hardened_available is True:
        return "available"
    if hardened_available == "already-hardened":
        return "already-hardened"
    if hardened_available == "mixed":
        return "mixed"
    if hardened_available == "version-gap":
        return "version-gap"
    if hardened_available is False:
        return "no-equivalent"
    return "not-checked"


STATUS_META = {
    "available":       ("green",  "available",      "Hardened equivalent at same major version"),
    "already-hardened":("teal",   "already hardened", "Already a Chainguard hardened action — no change needed"),
    "mixed":           ("purple", "mixed",          "Status varies by the version in use — see per-workflow detail"),
    "version-gap":     ("amber",  "version gap",    "Hardened action exists but only at a different major version"),
    "no-equivalent":   ("red",    "no equivalent",  "No hardened equivalent in the catalog"),
    "not-checked":     ("gray",   "not checked",    "Not yet resolved"),
}

FILTER_BUCKETS = [
    ("available",        "Available"),
    ("already-hardened", "Already hardened"),
    ("mixed",            "Mixed"),
    ("version-gap",      "Version gap"),
    ("no-equivalent",    "No equivalent"),
    ("not-checked",      "Not checked"),
]

BAR_COLORS = {
    "available":       "#22c478",
    "already-hardened":"#3aa6c2",
    "mixed":           "#9b7dff",
    "version-gap":     "#d99a2b",
    "no-equivalent":   "#e5484d",
    "not-checked":     "#6e6e78",
}


def esc(s):
    return html.escape(str(s)) if s is not None else ""


def pill(status_key):
    cls, label, tooltip = STATUS_META.get(status_key, ("gray", status_key, ""))
    return (f'<span class="pill {cls}" title="{esc(tooltip)}">'
            f'<span class="dot"></span>{esc(label)}</span>')


# ─── Derived stats helpers ───────────────────────────────────────────────────────

def _action_status_key(action):
    return _status_key(action.get("hardened_available"))


def _versions_label(occurrences):
    refs = sorted({(o.get("version") or o.get("ref")) for o in occurrences
                   if o.get("version") or o.get("ref")})
    if not refs:
        return "—"
    if len(refs) <= 3:
        return ", ".join(refs)
    return ", ".join(refs[:2]) + f" +{len(refs) - 2} more"


def _count_by_status(actions):
    counts = {}
    for a in actions:
        k = _action_status_key(a)
        counts[k] = counts.get(k, 0) + 1
    return counts


def _usage_counts(actions):
    total = 0
    repos = set()
    wfs = set()
    for a in actions:
        for o in a.get("occurrences", []):
            total += 1
            repos.add(o.get("repo", ""))
            wfs.add((o.get("repo", ""), o.get("workflow", "")))
    return total, repos, wfs


# ─── Shared components ───────────────────────────────────────────────────────────

STAT_CARD_META = [
    ("available",        "Available",        "accent", "drop-in hardened equivalents"),
    ("already-hardened", "Already hardened", "teal",   "no change needed"),
    ("mixed",            "Mixed",            "purple", "status varies by version"),
    ("version-gap",      "Version gap",      "warn",   "major version jump required"),
    ("no-equivalent",    "No equivalent",    "danger", "not in the catalog"),
    ("not-checked",      "Not checked",      "muted",  "not resolved"),
]


def stat_cards(counts, total_usages, n_workflows):
    """One card per non-zero status bucket (+ a usages card), built from the SAME
    counts as the filter chips so the top numbers always match the table."""
    cards = []
    for key, label, cls, delta in STAT_CARD_META:
        c = counts.get(key, 0)
        if c == 0:
            continue
        cards.append(
            f'<div class="stat-card {cls}"><div class="label">{esc(label)}</div>'
            f'<div class="value">{c}</div><div class="delta">{esc(delta)}</div></div>'
        )
    cards.append(
        f'<div class="stat-card muted"><div class="label">Total usages</div>'
        f'<div class="value">{total_usages}</div>'
        f'<div class="delta">across {n_workflows} workflow{"s" if n_workflows != 1 else ""}</div></div>'
    )
    return '<div class="stat-grid">' + "".join(cards) + "</div>"


def filter_chips(counts):
    total = sum(counts.values())
    # Single-select: "All" is active by default; categories start inactive.
    chips = [f'<button class="chip active" data-filter="all">All <span class="count">{total}</span></button>']
    for status, label in FILTER_BUCKETS:
        c = counts.get(status, 0)
        if c == 0:
            continue
        chips.append(f'<button class="chip" data-filter="{status}">'
                     f'{esc(label)} <span class="count">{c}</span></button>')
    return "".join(chips)


def breakdown_bars(counts, total):
    rows = []
    for status in ["available", "already-hardened", "mixed", "version-gap", "no-equivalent", "not-checked"]:
        count = counts.get(status, 0)
        if count == 0:
            continue
        pct = (count / total * 100) if total else 0
        label = STATUS_META[status][1]
        color = BAR_COLORS[status]
        rows.append(f'''
          <div class="bar-row">
            <div class="label"><span class="swatch" style="background:{color}"></span>{esc(label)}</div>
            <div class="track"><div class="fill" style="width:{pct:.1f}%;background:{color}"></div></div>
            <div class="num">{count}</div>
          </div>''')
    return "\n".join(rows)


def actions_table(actions, filterable=False):
    rows = []
    for a in actions:
        sk = _action_status_key(a)
        occ = a.get("occurrences", [])
        repos = {o.get("repo", "") for o in occ}
        wfs = {(o.get("repo", ""), o.get("workflow", "")) for o in occ}
        versions = _versions_label(occ)
        hardened_ref = a.get("hardened_ref") or ""
        hardened_note = a.get("hardened_note") or ""

        if hardened_ref:
            ref_html = (f'<span class="code-inline">{esc(hardened_ref)}</span>'
                        f' <button class="copy-btn" data-copy="{esc(hardened_ref)}">copy</button>')
        else:
            ref_html = '<span class="muted">—</span>'

        note_html = f'<span style="font-size:11px">{esc(hardened_note)}</span>' if hardened_note else ""

        rows.append(f'''
          <tr data-status="{sk}">
            <td class="mono">{esc(a.get("action") or a.get("name", ""))}</td>
            <td class="mono muted">{esc(versions)}</td>
            <td class="num">{len(repos)}</td>
            <td class="num">{len(wfs)}</td>
            <td class="num">{len(occ)}</td>
            <td>{pill(sk)}</td>
            <td>{ref_html}</td>
            <td class="muted">{note_html}</td>
          </tr>''')

    cls = "table filterable" if filterable else "table"
    return f'''
      <table class="{cls}">
        <thead><tr>
          <th>Action</th>
          <th>Versions in use</th>
          <th class="num">Repos</th>
          <th class="num">Workflows</th>
          <th class="num">Usages</th>
          <th>Status</th>
          <th>Hardened ref</th>
          <th>Notes</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>'''


def workflow_detail_card(workflow_path, items):
    """items: list of (action_name, occ_list, action_obj)"""
    rows = []
    for action_name, occ_list, a_obj in items:
        for occ in occ_list:
            # Per-occurrence status/ref so a gap version and an available version
            # of the same action render distinctly on their own lines.
            ha = occ.get("hardened_available", a_obj.get("hardened_available"))
            sk = _status_key(ha)
            hardened_ref = occ.get("hardened_ref", a_obj.get("hardened_ref")) or ""
            if hardened_ref and ha in (True, "version-gap"):
                ref_html = (f'<span class="code-arrow">&#8594;</span>'
                            f'<span class="code-inline">{esc(hardened_ref)}</span>'
                            f' <button class="copy-btn" data-copy="{esc(hardened_ref)}">copy</button>')
            else:
                ref_html = '<span class="muted">—</span>'
            ver = occ.get("version") or occ.get("ref", "")
            rows.append(f'''
              <tr data-status="{sk}">
                <td class="num muted">{esc(str(occ.get("line", "")))}</td>
                <td class="mono">{esc(action_name)}@{esc(ver)}</td>
                <td>{ref_html}</td>
                <td>{pill(sk)}</td>
              </tr>''')

    return f'''
      <div class="card">
        <div class="card-header">
          <span class="path">{esc(workflow_path)}</span>
          <span class="meta">{len(rows)} ref{"s" if len(rows) != 1 else ""}</span>
        </div>
        <table class="table">
          <thead><tr>
            <th class="num">Line</th>
            <th>Current</th>
            <th>Hardened ref</th>
            <th>Status</th>
          </tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>'''


# ─── Repo-scope view ─────────────────────────────────────────────────────────────

def render_repo(data):
    repo = data.get("repo", "(local)")
    actions = data.get("actions", [])
    version_strategy = data.get("version_strategy", "same-major")
    scanned_at = (data.get("scanned_at") or "")[:10]

    total_usages, repos_set, wfs_set = _usage_counts(actions)
    counts = _count_by_status(actions)
    n_available = counts.get("available", 0)
    n_gap = counts.get("version-gap", 0)
    n_no_equiv = counts.get("no-equivalent", 0)

    # Build workflow -> {action -> (action_obj, [occs])}
    wf_map = {}
    for a in actions:
        for occ in a.get("occurrences", []):
            wf = occ.get("workflow", "")
            if wf not in wf_map:
                wf_map[wf] = {}
            aname = a.get("action") or a.get("name", "")
            if aname not in wf_map[wf]:
                wf_map[wf][aname] = (a, [])
            wf_map[wf][aname][1].append(occ)

    wf_cards = []
    for wf_path in sorted(wf_map.keys()):
        items = [(aname, occs, a_obj) for aname, (a_obj, occs) in wf_map[wf_path].items()]
        wf_cards.append(workflow_detail_card(wf_path, items))

    chips_html = filter_chips(counts)
    subtitle_scan = f" · scanned {esc(scanned_at)}" if scanned_at else ""

    return _wrap(
        title=f"cg-actions · {repo}",
        topbar_scope=f"repo · {repo}",
        body=f'''
        <div class="page-header">
          <div class="breadcrumb">cg-actions / repo</div>
          <h1>{esc(repo)}</h1>
          <div class="subtitle">
            <strong>{len(actions)}</strong> distinct action{"s" if len(actions) != 1 else ""} ·
            <strong>{total_usages}</strong> total usage{"s" if total_usages != 1 else ""} across
            <strong>{len(wfs_set)}</strong> workflow{"s" if len(wfs_set) != 1 else ""} ·
            strategy: <code>{esc(version_strategy)}</code>{subtitle_scan}
          </div>
        </div>

        {stat_cards(counts, total_usages, len(wfs_set))}

        <div class="card">
          <div class="card-header">
            <h3>Actions inventory</h3>
            <span class="meta">{len(actions)} distinct</span>
          </div>
          <div class="chips">{chips_html}</div>
          <div style="overflow-x:auto">{actions_table(actions, filterable=True)}</div>
        </div>

        <div class="section-title" style="margin-top:28px">By workflow</div>
        {"".join(wf_cards) or
         '<div class="card" style="padding:16px;color:var(--text-3)">No workflow files found.</div>'}

        <footer>Generated {esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} · cg-actions skill</footer>
        ''')


# ─── Org-scope view ──────────────────────────────────────────────────────────────

def render_org(data):
    org = data.get("org", "(unknown)")
    actions = data.get("actions", [])
    version_strategy = data.get("version_strategy", "same-major")
    scanned_at = (data.get("scanned_at") or "")[:10]

    total_usages, repos_set, wfs_set = _usage_counts(actions)
    counts = _count_by_status(actions)
    n_available = counts.get("available", 0)
    n_gap = counts.get("version-gap", 0)
    n_no_equiv = counts.get("no-equivalent", 0)

    # Build per-repo action map
    repo_action_map = {}
    for a in actions:
        for occ in a.get("occurrences", []):
            r = occ.get("repo", "")
            if r not in repo_action_map:
                repo_action_map[r] = {}
            aname = a.get("action") or a.get("name", "")
            repo_action_map[r][aname] = a  # last occurrence wins (same action_obj)

    repo_summaries = []
    for r, amap in repo_action_map.items():
        r_actions = list(amap.values())
        r_counts = _count_by_status(r_actions)
        r_total, _, r_wfs = _usage_counts(r_actions)
        repo_summaries.append({
            "repo": r,
            "actions": r_actions,
            "counts": r_counts,
            "total_usages": r_total,
            "wf_count": len(r_wfs),
            "actionable": r_counts.get("available", 0) + r_counts.get("version-gap", 0),
        })
    repo_summaries.sort(key=lambda x: -x["actionable"])

    # Top repos panel
    attention_rows = []
    for rs in repo_summaries[:8]:
        pills_html = []
        for st in ("available", "version-gap", "no-equivalent"):
            c = rs["counts"].get(st, 0)
            if c == 0:
                continue
            cls = STATUS_META[st][0]
            label = STATUS_META[st][1]
            pills_html.append(f'<span class="pill {cls}"><span class="dot"></span>{c} {esc(label)}</span>')
        attention_rows.append(f'''
          <div class="feed-row">
            <div>
              <div class="repo">{esc(rs["repo"])}</div>
              <div class="detail">{rs["wf_count"]} workflow{"s" if rs["wf_count"] != 1 else ""} · {rs["total_usages"]} usage{"s" if rs["total_usages"] != 1 else ""}</div>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">{"".join(pills_html)}</div>
          </div>''')
    if not attention_rows:
        attention_rows.append('<div class="feed-row"><div class="detail">No repos with actionable swaps.</div></div>')

    # Per-repo detail cards (no chips — the single filter lives on the All actions
    # table above, so per-repo tables are always shown in full).
    repo_cards = []
    for rs in repo_summaries:
        repo_cards.append(f'''
          <div class="card">
            <div class="card-header">
              <span class="path">{esc(rs["repo"])}</span>
              <span class="meta">{len(rs["actions"])} action{"s" if len(rs["actions"]) != 1 else ""} · {rs["total_usages"]} usage{"s" if rs["total_usages"] != 1 else ""}</span>
            </div>
            <div style="overflow-x:auto">{actions_table(rs["actions"])}</div>
          </div>''')

    chips_html_top = filter_chips(counts)
    subtitle_scan = f" · scanned {esc(scanned_at)}" if scanned_at else ""

    return _wrap(
        title=f"cg-actions · {org}",
        topbar_scope=f"org · {org}",
        body=f'''
        <div class="page-header">
          <div class="breadcrumb">cg-actions / org</div>
          <h1>{esc(org)}</h1>
          <div class="subtitle">
            <strong>{len(repos_set)}</strong> repos ·
            <strong>{len(actions)}</strong> distinct action{"s" if len(actions) != 1 else ""} ·
            <strong>{total_usages}</strong> total usages ·
            strategy: <code>{esc(version_strategy)}</code>{subtitle_scan}
          </div>
        </div>

        {stat_cards(counts, total_usages, len(wfs_set))}

        <div class="split">
          <div class="card">
            <div class="card-header">
              <h3>Findings by status</h3>
              <span class="meta">{len(actions)} actions</span>
            </div>
            <div class="bars">{breakdown_bars(counts, len(actions))}</div>
          </div>
          <div class="card">
            <div class="card-header">
              <h3>Top repos by actionable swaps</h3>
              <span class="meta">top {min(8, len(repo_summaries))} of {len(repo_summaries)}</span>
            </div>
            {"".join(attention_rows)}
          </div>
        </div>

        <div class="card" style="margin-bottom:28px">
          <div class="card-header">
            <h3>All actions</h3>
            <span class="meta">{len(actions)} distinct</span>
          </div>
          <div class="chips">{chips_html_top}</div>
          <div style="overflow-x:auto">{actions_table(actions, filterable=True)}</div>
        </div>

        <div class="section-title">By repo</div>
        {"".join(repo_cards)}

        <footer>Generated {esc(datetime.now().strftime("%Y-%m-%d %H:%M"))} · cg-actions skill</footer>
        ''')


# ─── Page wrapper ────────────────────────────────────────────────────────────────

def _wrap(*, title, topbar_scope, body):
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body data-show-available="1" data-show-already-hardened="1" data-show-mixed="1" data-show-version-gap="1" data-show-no-equivalent="1" data-show-not-checked="1">

<header class="topbar">
  <div class="brand">&#127807; cg-actions</div>
  <div class="scope">{esc(topbar_scope)}</div>
  <div class="right">
    <span class="meta">{esc(datetime.now().strftime("%Y-%m-%d %H:%M"))}</span>
  </div>
</header>

<main class="page">
{body}
</main>

<script>{JS}</script>
</body>
</html>
'''


# ─── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", default="-",
                        help="inventory.json path, or - for stdin (default: -)")
    parser.add_argument("--no-open", action="store_true",
                        help="Write the file but don't auto-open in browser")
    parser.add_argument("-o", "--output",
                        help="Output file path (default: auto tempfile)")
    args = parser.parse_args()

    if args.input == "-":
        source = sys.stdin
    else:
        try:
            source = open(args.input, encoding="utf-8")
        except OSError as e:
            sys.exit(f"Cannot open {args.input}: {e}")

    try:
        data = json.load(source)
    except json.JSONDecodeError as e:
        sys.exit(f"Invalid JSON: {e}")
    finally:
        if source is not sys.stdin:
            source.close()

    # Infer scope from keys if not explicit
    scope = data.get("scope")
    if scope is None:
        if "org" in data:
            scope = "org"
        elif "repo" in data:
            scope = "repo"

    if scope == "org":
        html_content = render_org(data)
    elif scope == "repo":
        html_content = render_repo(data)
    else:
        sys.exit(f"Cannot determine scope from inventory (no 'scope', 'org', or 'repo' key).")

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.write_text(html_content, encoding="utf-8")
    else:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", prefix="cg-actions-",
            delete=False, encoding="utf-8")
        tmp.write(html_content)
        tmp.close()
        out_path = Path(tmp.name)

    print(out_path)

    if not args.no_open:
        if sys.platform == "darwin":
            subprocess.run(["open", str(out_path)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(out_path)], check=False)


if __name__ == "__main__":
    main()
