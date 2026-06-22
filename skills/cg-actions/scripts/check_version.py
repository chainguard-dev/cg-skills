#!/usr/bin/env python3
"""
check_version.py — is this cg-actions skill the latest published version?

Compares the local VERSION file against the VERSION published on the skill's
GitHub repo (default branch). Prints a one-line status; if a newer version
exists, prints an update suggestion. Never fails the run — a network/auth issue
just yields "could not check for updates".

Usage:
    python3 scripts/check_version.py
    python3 scripts/check_version.py --quiet   # print only when an update exists
"""
import argparse
import base64
import os
import subprocess
import sys
import urllib.request

REPO = "chainguard-dev/cg-skills"          # canonical source of the skill
VERSION_PATH = "skills/cg-actions/VERSION"  # location of VERSION within REPO
HERE = os.path.dirname(os.path.abspath(__file__))


def local_version():
    try:
        with open(os.path.join(HERE, "..", "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def remote_version():
    """Latest published VERSION. Prefer gh (already a skill prerequisite); fall
    back to the raw URL so the check still works without gh."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{REPO}/contents/{VERSION_PATH}", "--jq", ".content"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return base64.b64decode(r.stdout.strip()).decode("utf-8").strip()
    except Exception:
        pass
    try:
        url = f"https://raw.githubusercontent.com/{REPO}/main/{VERSION_PATH}"
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (fixed host)
            return resp.read().decode("utf-8").strip()
    except Exception:
        return None


def _parse(v):
    """Loose semver tuple, tolerant of suffixes like '1.2.0-rc1'."""
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true",
                    help="print only when an update is available")
    args = ap.parse_args(argv)

    loc = local_version()
    rem = remote_version()

    if not loc:
        if not args.quiet:
            print("cg-actions: local VERSION file not found.")
        return 0
    if not rem:
        if not args.quiet:
            print(f"cg-actions v{loc} (could not check for updates).")
        return 0

    if _parse(rem) > _parse(loc):
        print(f"⚠️ cg-actions is out of date: you have v{loc}, latest is v{rem}.")
        print(f"   Update by downloading the latest from https://github.com/{REPO}")
    elif not args.quiet:
        print(f"cg-actions v{loc} (up to date).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
