# php-2026-11

An agent skill that helps Chainguard customers find, verify and remediate images and packages affected by the **PHP security release of 2026-11-19**: 17 vulnerabilities (7 critical) fixed upstream in PHP 8.2.36, 8.3.37, 8.4.28 and 8.5.13.

It turns the steps in Chainguard's KB article for this release into instructions an agent can carry out in your environment. The KB article remains the authority.

## What it does

1. **Inventories** Chainguard image references in your repositories (manifests, Helm values, Compose, Terraform, Dockerfiles, plus your mirror prefixes), the images running in your Kubernetes clusters, Dockerfiles and apko configs that install PHP packages, and the PHP configuration they use.
2. **Verifies** each image by reading every PHP package from the signed SBOM attestation, including each extension and SAPI subpackage, and its filesystem for PHP the SBOM doesn't list, such as a binary copied in from a build stage. An image with a fixed `php-8.N` but an extension from the previous release is still vulnerable. FrankenPHP images are decided from their `php-8.N-frankenphp` package, because FrankenPHP's startup log reports the PHP version it was compiled against.
3. **Reports which CVEs apply** to each image from the SAPIs and extensions installed (FPM, CGI, SOAP, DOM, Phar) and, for CVE-2026-115560, from the `session.upload_progress.enabled` setting. This sets priority; it never makes a vulnerable build count as fixed.
4. **Plans the fix** for each affected reference: tag, digest pin, mirror, derived image, copied binary, `apk add` pins on any PHP subpackage, apko lockfile, Custom Assembly, or end-of-life PHP 8.1.
5. **Applies approved changes**, preferring a pull request through your normal change process, then **re-verifies** the images actually running and writes a remediation report.

## Safety model

- Discovery and verification are read-only. Images are inspected, never run.
- Every change (file edits, image copies, builds, deploys, restarts, PHP configuration) is shown first and needs explicit approval, one change at a time.
- It never sends exploit traffic, never skips signature verification or uses insecure registry flags, and never handles credentials.
- Anything it can't verify is reported as `UNKNOWN`, never as patched.
- It stops and points to Chainguard Support when a fix isn't in your registry yet or a signature fails.

## Requirements

An agent with a shell tool (for example Claude Code) and: `docker` (or `podman`), `cosign`, `jq`, `crane`, `chainctl` (logged in), and `kubectl` if Kubernetes is in scope. The skill checks for these and reports anything missing; it doesn't install software. The filesystem check needs free disk space of about twice the size of the largest image it inspects.

## Install

```sh
chainctl skills install skills.cgr.dev/chainguard/chainguard-dev/php-2026-11:latest
```

For local development, copy this directory into your agent's skills directory instead.

## Updating for later rounds

All incident-specific facts live in the **Incident data** YAML block in [SKILL.md](SKILL.md): CVEs with their component and branches, advisories, fixed versions per package, end-of-life lines, the SBOM rule, where each component's code is installed, FrankenPHP's version strings, shipped defaults, scanner feeds, signature verification commands and support links. Update that block, and bump [VERSION](VERSION), when the KB article changes.
