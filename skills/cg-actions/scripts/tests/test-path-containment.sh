#!/bin/sh
# Fixture tests for the local workflow readers (discover.py --local,
# scan_workflows.py, rewrite_workflows.py --repo). An audited checkout is
# untrusted: a workflow entry that is a symlink pointing outside the checkout
# must be skipped with a warning, never read. A symlink that stays inside the
# checkout is a legitimate layout and must still be scanned.
#
# Dependencies: sh, python3, grep. No network: a stub gh on PATH fails every
# catalog lookup.

set -u

SCRIPTS="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)" || exit 1
trap 'rm -rf "$tmp"' EXIT INT TERM

pass=0
failcount=0
ok() { pass=$((pass + 1)); echo "ok - $1"; }
fail() { failcount=$((failcount + 1)); echo "FAIL - $1"; }

mkdir -p "$tmp/bin" "$tmp/outside" "$tmp/repo/.github/workflows" "$tmp/repo/shared" "$tmp/out"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/gh"
chmod +x "$tmp/bin/gh"
PATH="$tmp/bin:$PATH"
export PATH

printf 'jobs:\n  a:\n    steps:\n      - uses: outside/leak@v1\n' > "$tmp/outside/foreign.yml"
printf 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n' > "$tmp/repo/.github/workflows/ci.yml"
printf 'jobs:\n  a:\n    steps:\n      - uses: inside/shared@v2\n' > "$tmp/repo/shared/release.yml"
ln -s "$tmp/outside/foreign.yml" "$tmp/repo/.github/workflows/escape.yml"
ln -s ../../shared/release.yml "$tmp/repo/.github/workflows/release.yml"

check() { # name, stdout file, stderr file
  if grep -q 'outside/leak' "$2"; then fail "$1: read a workflow outside the checkout"
  else ok "$1: did not read the escaping symlink"; fi
  if grep -q 'escape.yml' "$3"; then ok "$1: warned about escape.yml"
  else fail "$1: skipped escape.yml silently"; fi
  if grep -q 'actions/checkout' "$2" && grep -q 'inside/shared' "$2"; then
    ok "$1: still scanned the regular file and the in-checkout symlink"
  else fail "$1: lost a legitimate workflow"; fi
}

python3 "$SCRIPTS/discover.py" --local "$tmp/repo" > "$tmp/d.out" 2> "$tmp/d.err"
check discover "$tmp/d.out" "$tmp/d.err"

python3 "$SCRIPTS/scan_workflows.py" "$tmp/repo" > "$tmp/s.out" 2> "$tmp/s.err"
check scan_workflows "$tmp/s.out" "$tmp/s.err"

printf '{"actions/checkout": "chainguard-actions/actions-checkout@v4", "inside/shared": "x/y@v2"}\n' > "$tmp/map.json"
python3 "$SCRIPTS/rewrite_workflows.py" --mapping "$tmp/map.json" --out-dir "$tmp/out" \
  --repo "$tmp/repo" > "$tmp/r.out" 2> "$tmp/r.err"
check rewrite_workflows "$tmp/r.out" "$tmp/r.err"

# An explicit file outside --base-dir would land outside --out-dir.
python3 "$SCRIPTS/rewrite_workflows.py" --mapping "$tmp/map.json" --out-dir "$tmp/out" \
  --base-dir "$tmp/repo" "$tmp/outside/foreign.yml" > /dev/null 2> "$tmp/r2.err"
rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$tmp/outside/foreign.yml.diff" ] && grep -q 'outside' "$tmp/r2.err"; then
  ok "rewrite_workflows: refused an output path outside --out-dir"
else fail "rewrite_workflows: wrote outside --out-dir (rc=$rc)"; fi

echo "$pass passed, $failcount failed"
[ "$failcount" -eq 0 ]
