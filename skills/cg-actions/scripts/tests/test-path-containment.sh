#!/bin/sh
# Fixture tests for the local workflow readers (discover.py --local,
# scan_workflows.py, rewrite_workflows.py --repo). An audited checkout is
# untrusted: a workflow entry that is a symlink pointing outside the checkout
# must be skipped with a warning, never read, and a symlink loop must be skipped,
# not crash the reader. A symlink that stays inside the checkout is a legitimate
# layout and must still be scanned.
#
# Dependencies: sh, python3 (override with PYTHON=), grep. No network: a stub gh
# on PATH fails every catalog lookup.

set -u
PY="${PYTHON:-python3}"

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
ln -s b.yml "$tmp/repo/.github/workflows/a.yml"
ln -s a.yml "$tmp/repo/.github/workflows/b.yml"

check() { # name, stdout file, stderr file, exit code
  if [ "$4" -eq 0 ]; then ok "$1: exited 0"
  else fail "$1: exited $4"; fi
  if grep -q 'outside/leak' "$2"; then fail "$1: read a workflow outside the checkout"
  else ok "$1: did not read the escaping symlink"; fi
  if grep -q 'escape.yml' "$3"; then ok "$1: warned about escape.yml"
  else fail "$1: skipped escape.yml silently"; fi
  if grep -q 'actions/checkout' "$2" && grep -q 'inside/shared' "$2"; then
    ok "$1: still scanned the regular file and the in-checkout symlink"
  else fail "$1: lost a legitimate workflow"; fi
  if grep -q 'workflows/a\.yml' "$3" && grep -q 'workflows/b\.yml' "$3"; then ok "$1: warned about the symlink loop"
  else fail "$1: skipped the symlink loop silently"; fi
}

# rewrite_workflows exits 2 here (nothing left to rewrite), so check for a crash, not rc 0.
check_dir_escape() { # name, stdout file, stderr file, exit code
  if ! grep -q Traceback "$3" && ! grep -q 'outside/leak' "$2" && grep -q 'foreign\.yml' "$3"; then
    ok "$1: skipped a symlinked dir that leaves the checkout"
  else fail "$1: followed a symlinked dir out of the checkout (rc=$4)"; fi
}

check_dir_inside() { # name, stdout file, exit code
  if [ "$3" -eq 0 ] && grep -q 'actions/checkout' "$2"; then
    ok "$1: scanned a symlinked workflows dir inside the checkout"
  else fail "$1: lost a symlinked workflows dir inside the checkout (rc=$3)"; fi
}

run_readers() { # repo, tag
  "$PY" "$SCRIPTS/discover.py" --local "$1" > "$tmp/d$2.out" 2> "$tmp/d$2.err"; echo $? > "$tmp/d$2.rc"
  "$PY" "$SCRIPTS/scan_workflows.py" "$1" > "$tmp/s$2.out" 2> "$tmp/s$2.err"; echo $? > "$tmp/s$2.rc"
  "$PY" "$SCRIPTS/rewrite_workflows.py" --mapping "$tmp/map.json" --out-dir "$tmp/out$2" \
    --repo "$1" > "$tmp/r$2.out" 2> "$tmp/r$2.err"; echo $? > "$tmp/r$2.rc"
}

printf '{"actions/checkout": "chainguard-actions/actions-checkout@v4", "inside/shared": "x/y@v2"}\n' > "$tmp/map.json"

run_readers "$tmp/repo" ""
for t in d s r; do
  case $t in d) n=discover ;; s) n=scan_workflows ;; r) n=rewrite_workflows ;; esac
  check "$n" "$tmp/$t.out" "$tmp/$t.err" "$(cat "$tmp/$t.rc")"
done

# .github/workflows itself a symlink: inside the checkout is fine, outside is not.
mkdir -p "$tmp/dirin/.github" "$tmp/dirin/ci" "$tmp/dirout/.github" "$tmp/ghout" "$tmp/outwf/.github/workflows"
cp "$tmp/repo/.github/workflows/ci.yml" "$tmp/dirin/ci/ci.yml"
ln -s ../ci "$tmp/dirin/.github/workflows"
cp "$tmp/outside/foreign.yml" "$tmp/outwf/.github/workflows/foreign.yml"
ln -s "$tmp/outwf/.github/workflows" "$tmp/dirout/.github/workflows"
ln -s "$tmp/outwf/.github" "$tmp/ghout/.github"
run_readers "$tmp/dirin" "-in"
run_readers "$tmp/dirout" "-out"
run_readers "$tmp/ghout" "-gh"
for t in d s r; do
  case $t in d) n=discover ;; s) n=scan_workflows ;; r) n=rewrite_workflows ;; esac
  check_dir_inside "$n" "$tmp/$t-in.out" "$(cat "$tmp/$t-in.rc")"
  check_dir_escape "$n (workflows dir)" "$tmp/$t-out.out" "$tmp/$t-out.err" "$(cat "$tmp/$t-out.rc")"
  check_dir_escape "$n (.github dir)" "$tmp/$t-gh.out" "$tmp/$t-gh.err" "$(cat "$tmp/$t-gh.rc")"
done

# An explicit file outside --base-dir would land outside --out-dir. It comes
# after an in-bounds file, which must not be written either.
"$PY" "$SCRIPTS/rewrite_workflows.py" --mapping "$tmp/map.json" --out-dir "$tmp/out2" \
  --base-dir "$tmp/repo" "$tmp/repo/.github/workflows/ci.yml" "$tmp/outside/foreign.yml" \
  > /dev/null 2> "$tmp/r2.err"
rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$tmp/outside/foreign.yml.diff" ] && grep -q 'outside' "$tmp/r2.err"; then
  ok "rewrite_workflows: refused an output path outside --out-dir"
else fail "rewrite_workflows: wrote outside --out-dir (rc=$rc)"; fi
if [ -z "$(find "$tmp/out2" -type f 2>/dev/null)" ]; then
  ok "rewrite_workflows: wrote nothing when any target was out of bounds"
else fail "rewrite_workflows: wrote $(find "$tmp/out2" -type f | wc -l | tr -d ' ') file(s) before refusing"; fi

echo "$pass passed, $failcount failed"
[ "$failcount" -eq 0 ]
