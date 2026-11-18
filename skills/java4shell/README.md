# java4shell

An agent skill that helps Chainguard customers find, verify and remediate images and packages affected by Oracle's **November 2026 Critical Security Patch Update** for Java SE, released on 2026-11-17. The update includes **CVE-2026-114938**, known as Java4Shell, an unauthenticated remote code execution in OpenJDK 17, 21, 25 and 27, and fixes for Java 8 and 11.

It turns the steps in Chainguard's KB article (*"ACTION REQUIRED: Update Chainguard images with OpenJDK for Oracle's November 2026 Critical Security Patch Update"*) into instructions an agent can carry out in your environment. The KB article remains the authority.

## What it does

1. **Inventories** Chainguard image references in your repositories (manifests, Helm values, Compose, Terraform, Dockerfiles, plus your mirror prefixes), the images running in your Kubernetes clusters, Dockerfiles that `apk add` JDK packages, and builds that make their own runtime with `jlink`, `native-image` or a JDK copied between build stages.
2. **Verifies** each image by reading its JDK packages from the signed SBOM attestation, and its filesystem for Java the SBOM doesn't list: embedded runtimes (ontop, kafka-native), jlinked or copied runtimes, and GraalVM native executables. It compares versions with apk's own comparator, which handles four- and five-part versions such as `17.0.21.1` and Corretto's `17.0.21.1.2`.
3. **Plans the fix** for each affected reference: tag, digest pin, mirror, derived image, jlink or copied runtime, `apk add` pin, apko lockfile, Custom Assembly, embedded runtime, or vendor JDK.
4. **Applies approved changes**, preferring a pull request through your normal change process, then **re-verifies** the images actually running and writes a remediation report.

## Safety model

- Discovery and verification are read-only. Images are inspected, never run.
- Every change (file edits, image copies, builds, deploys, restarts, JVM options) is shown first and needs explicit approval, one change at a time.
- It never skips signature verification or uses insecure registry flags, and never handles credentials.
- Anything it can't verify is reported as `UNKNOWN`, never as patched.
- It stops and points to Chainguard Support when a fix isn't in your registry yet or a signature fails.

## Requirements

An agent with a shell tool (for example Claude Code) and: `docker` (or `podman`), `cosign`, `jq`, `crane`, `chainctl` (logged in), and `kubectl` if Kubernetes is in scope. The skill checks for these and reports anything missing; it doesn't install software. The filesystem check needs free disk space of about twice the size of the largest image it inspects.

## Install

```sh
chainctl skills install skills.cgr.dev/chainguard/chainguard-dev/java4shell:latest
```

For local development, copy this directory into your agent's skills directory instead.

## Updating for later rounds

All incident-specific facts live in the **Incident data** YAML block in [SKILL.md](SKILL.md): CVEs, advisories, fixed versions per JDK package, upstream fixed versions per Java line, embedded runtimes, affected images, scanner feeds, signature verification commands and support links. Update that block, and bump [VERSION](VERSION), when the KB article changes.
