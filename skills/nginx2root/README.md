# nginx2root

An agent skill that helps Chainguard customers find, verify and remediate images and packages affected by **NGINX2Root**: five unauthenticated NGINX vulnerabilities disclosed on 2026-11-18 (CVE-2026-123633, CVE-2026-123007, CVE-2026-123634, CVE-2026-121810 and CVE-2026-113425), fixed upstream in NGINX 1.31.9 and 1.30.7 and in NGINX Plus 37.3.0.1.

It turns the steps in Chainguard's KB article (*"[ACTION REQUIRED] NGINX security updates (NGINX2Root): update Chainguard images that include NGINX"*) into instructions an agent can carry out in your environment. The KB article remains the authority.

## What it does

1. **Inventories** Chainguard image references in your repositories (manifests, Helm values, Compose, Terraform, Dockerfiles, plus your mirror prefixes), the images running in your Kubernetes clusters, Dockerfiles and apko configs that install NGINX packages (including from the public package repository, which keeps unfixed nginx-stable and kong builds), and the NGINX configuration they use.
2. **Verifies** each image by reading its NGINX packages from the signed SBOM attestation, and its filesystem for NGINX the SBOM doesn't list, such as a binary copied in from a build stage. It decides from the package version and revision, because backported fixes don't change the version string that `nginx -v` reports (ingress-nginx-controller, Kong, OpenResty, Apache APISIX, NGINX Plus).
3. **Checks exposure** for each CVE in the NGINX configuration: HTTP/2 listeners, resolver-driven proxying, HTTP/3 `quic` listeners and the mail proxy. Exposure sets priority and stopgaps; it never makes a vulnerable build count as fixed.
4. **Plans the fix** for each affected reference: tag, digest pin, mirror, derived image, copied binary, `apk add` pin or public repository, apko lockfile, Custom Assembly, end-of-life ingress-nginx-controller lines, or the nginx-gateway-fabric data plane.
5. **Applies approved changes**, preferring a pull request through your normal change process, then **re-verifies** the images actually running and writes a remediation report.

## Safety model

- Discovery and verification are read-only. Images are inspected, never run. Reading a running container's configuration with `nginx -T` is asked for first.
- Every change (file edits, image copies, builds, deploys, restarts, NGINX configuration) is shown first and needs explicit approval, one change at a time.
- It never sends exploit traffic, never skips signature verification or uses insecure registry flags, and never handles credentials.
- Anything it can't verify is reported as `UNKNOWN`, never as patched.
- It stops and points to Chainguard Support when a fix isn't in your registry yet or a signature fails.

## Requirements

An agent with a shell tool (for example Claude Code) and: `docker` (or `podman`), `cosign`, `jq`, `crane`, `chainctl` (logged in), and `kubectl` if Kubernetes is in scope. The skill checks for these and reports anything missing; it doesn't install software. The filesystem check needs free disk space of about twice the size of the largest image it inspects.

## Install

```sh
chainctl skills install skills.cgr.dev/chainguard/chainguard-dev/nginx2root:latest
```

For local development, copy this directory into your agent's skills directory instead.

## Updating for later rounds

All incident-specific facts live in the **Incident data** YAML block in [SKILL.md](SKILL.md): CVEs and what each needs, advisories, fixed versions per package, partial and end-of-life builds, what each package compiles in, shipped defaults, scanner feeds, signature verification commands and support links. Update that block, and bump [VERSION](VERSION), when the KB article changes.
