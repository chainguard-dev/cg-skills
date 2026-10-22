# gitlab-onigmo

An agent skill that helps Chainguard customers find, verify and remediate images and packages affected by
**CVE-2026-110264** (critical GitLab remote code execution, CVSS 10.0), disclosed by GitLab on 2026-10-21.

The root cause is a bug in Onigmo, the regular expression engine built into Ruby. GitLab's own packages
bundle a patched Ruby. Chainguard images run GitLab on Chainguard's Ruby packages, which carry the same
upstream fixes, so the skill checks the **Ruby package version**, not just the GitLab version. Ruby has no
CVE for this bug, so scanners won't confirm the fix, and Ruby images other than GitLab aren't flagged at all.

It turns the steps in Chainguard's KB article (*"ACTION REQUIRED: Update Chainguard GitLab and Ruby images
for CVE-2026-110264"*) into instructions an agent can carry out in your environment.
The KB article remains the authority.

## What it does

1. **Inventories** Chainguard image references in your repositories (manifests, Helm values, Compose,
   Terraform, Dockerfiles, plus your mirror prefixes), the images running in your Kubernetes clusters,
   and Dockerfiles that `apk add` Ruby packages.
2. **Verifies** each image by reading the Ruby package version (and, for GitLab, the `gitlab-rails` version)
   from its SBOM attestation, and compares it to the fixed versions with apk's own version comparator.
   Text comparison would get `-r10` vs `-r9` wrong.
3. **Plans the fix** for each affected reference: tag, digest pin, mirror, derived image, `apk add` pin,
   Custom Assembly, an unsupported GitLab stream, or end-of-life Ruby 3.2 and earlier.
4. **Applies approved changes**, preferring a pull request through your normal change process, then
   **re-verifies** the images actually running and writes a remediation report.

## Safety model

- Discovery and verification are read-only.
- Every change (file edits, image copies, builds, deploys, restarts) is shown first and needs explicit
  approval, one change at a time.
- It never skips signature verification or uses insecure registry flags, and never handles credentials.
- It never tries to trigger the vulnerability. Verification is by package version only.
- Anything it can't verify is reported as `UNKNOWN`, never as patched.
- It stops and points to Chainguard Support when a fix isn't in your registry yet or a signature fails.

## Requirements

An agent with a shell tool (for example Claude Code) and: `docker` (or `podman`), `cosign`, `jq`, `crane`,
`chainctl` (logged in), and `kubectl` if Kubernetes is in scope. The skill checks for these and reports
anything missing; it doesn't install software.

## Install

```sh
chainctl skills install skills.cgr.dev/chainguard/chainguard-dev/gitlab-onigmo:latest
```

For local development, copy this directory into your agent's skills directory instead.

## Updating for later rounds

All incident-specific facts live in the **Incident data** YAML block in [SKILL.md](SKILL.md): fixed versions,
GitLab versions and components, affected images, scanner feeds, GitLab's detections, signature verification
commands and support links. Update that block, and bump [VERSION](VERSION), when the KB article changes.
