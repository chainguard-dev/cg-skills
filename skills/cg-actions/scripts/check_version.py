#!/usr/bin/env python3
"""
check_version.py — is this cg-actions skill the latest published version?

Detects how the skill was installed and checks the matching source:

  * Installed via Chainguard Agent Skills (`chainctl skills install ...`):
    files live under an `.agents/skills/` directory (usually via a symlink), so
    we ask the registry: `chainctl skills versions <org/name>`.
  * Installed from GitHub (clone or downloaded .skill): we compare against the
    `VERSION` file in the chainguard-dev/cg-skills repo.

Override detection with CG_ACTIONS_UPDATE_SOURCE=registry|github. If the detected
source can't be reached, the other is tried as a fallback. The check is
non-blocking: any network/auth issue just yields "could not check for updates".

Usage:
    python3 scripts/check_version.py
    python3 scripts/check_version.py --quiet   # print only when an update exists
"""
import argparse
import base64
import os
import re
import subprocess
import sys
import urllib.request

# GitHub source (manual / cloned / downloaded installs)
GH_REPO = "chainguard-dev/cg-skills"
GH_VERSION_PATH = "skills/cg-actions/VERSION"

# Registry source (Chainguard Agent Skills installs)
SKILL_REF = "skills.cgr.dev/chainguard/chainguard-dev/cg-actions"
SKILL_NAME = "chainguard/chainguard-dev/cg-actions"   # org/name for `chainctl skills versions`

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)

_VER_RE = re.compile(r"\bv?(\d+(?:\.\d+){1,2})\b")


def local_version():
    try:
        with open(os.path.join(SKILL_ROOT, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def detect_source():
    """Return 'registry' or 'github' based on where the skill was installed."""
    env = os.environ.get("CG_ACTIONS_UPDATE_SOURCE", "").strip().lower()
    if env in ("registry", "github"):
        return env
    # chainctl writes a canonical copy under `.agents/skills/` and symlinks each
    # agent's skills dir to it. So if our resolved path runs through
    # `.agents/skills/` (or the skill dir is itself a symlink), the registry is
    # the source of truth. Otherwise assume a GitHub-style manual install.
    real = os.path.realpath(SKILL_ROOT).replace("\\", "/")
    if "/.agents/skills/" in real or os.path.islink(SKILL_ROOT.rstrip("/")):
        return "registry"
    return "github"


def _max_version(text):
    """Largest vX.Y.Z-style token found in text, or None."""
    best, best_key = None, ()
    for m in _VER_RE.finditer(text or ""):
        key = tuple(int(x) for x in m.group(1).split("."))
        if key > best_key:
            best_key, best = key, m.group(1)
    return best


def registry_latest():
    """Latest published tag from the skills registry via chainctl."""
    for extra in (["-o", "json"], []):
        try:
            r = subprocess.run(
                ["chainctl", "skills", "versions", SKILL_NAME, *extra],
                capture_output=True, text=True,
            )
        except Exception:
            return None
        if r.returncode == 0 and r.stdout.strip():
            v = _max_version(r.stdout)
            if v:
                return v
    return None


def github_latest():
    """Latest published VERSION from the GitHub repo (gh, then raw URL)."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{GH_REPO}/contents/{GH_VERSION_PATH}", "--jq", ".content"],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return base64.b64decode(r.stdout.strip()).decode("utf-8").strip()
    except Exception:
        pass
    try:
        url = f"https://raw.githubusercontent.com/{GH_REPO}/main/{GH_VERSION_PATH}"
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


UPDATE_HINT = {
    "registry": f"Update: re-run  chainctl skills install {SKILL_REF}:latest",
    "github": f"Update: download the latest from https://github.com/{GH_REPO}",
}


def latest_version(source):
    """Latest version from the detected source, falling back to the other one."""
    order = [source, "github" if source == "registry" else "registry"]
    for src in order:
        rem = registry_latest() if src == "registry" else github_latest()
        if rem:
            return rem, src
    return None, source


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true",
                    help="print only when an update is available")
    args = ap.parse_args(argv)

    loc = local_version()
    source = detect_source()
    rem, used = latest_version(source)

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
        print("   " + UPDATE_HINT[used])
    elif not args.quiet:
        print(f"cg-actions v{loc} (up to date).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
