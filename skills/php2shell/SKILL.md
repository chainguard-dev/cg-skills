---
name: php2shell
description: >-
  Find, verify and remediate Chainguard images and packages affected by the
  critical PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619
  (unauthenticated RCE, CVSS v4.0 9.2) in this environment. Inventories image
  references in repos and running Kubernetes workloads, checks each image's SBOM
  for the PHP package version, proposes and (with approval) applies fixes for
  tag, digest-pinned, mirrored, Custom Assembly and apk-add builds, then
  re-verifies. Use when the user mentions these CVEs, "php2shell", Chainguard's
  PHP advisory, or asks "are we patched?".
---

# Remediate CVE-2026-109618 / CVE-2026-109619 in Chainguard PHP images

Published by Chainguard for its customers. This skill implements the steps in Chainguard's KB article
*"ACTION REQUIRED: Update Chainguard PHP images for CVE-2026-109618 and CVE-2026-109619"* so an agent
can carry them out in your environment. The human-readable KB remains the authority: if anything here
disagrees with it, follow the KB and tell the user.

## Ground rules for the agent (read first, follow always)

1. **Discovery and verification are read-only.** Run them freely.
2. **Every change needs the user's explicit approval first**: editing files, pushing or copying images,
   building, deploying, restarting workloads, changing policies. Show the exact diff or command, say what
   it affects, and wait for a yes. Approval for one change does not carry over to the next.
3. **Prefer the user's own change process.** If manifests live in Git (GitOps, Helm, Terraform), propose
   a branch or PR instead of changing a cluster directly. Ask before touching production.
4. **Never weaken security to make progress.** No skipping signature verification, no `--insecure` or
   `--allow-insecure-registry`, no disabling admission policies, no pinning *older* versions.
5. **Don't handle credentials.** If a registry, cluster or `chainctl` isn't authenticated, ask the user to
   log in themselves. Never print tokens or secrets.
6. **Report uncertainty instead of guessing.** If an image's SBOM can't be read, mark it `UNKNOWN`, never "patched".
7. **Stop and escalate** if a patched version isn't available in the user's registry (step 6), or a
   signature fails to verify.

## Incident data (single source of truth: update this block for later rounds)

```yaml
cves: [CVE-2026-109618, CVE-2026-109619]
advisories: {CVE-2026-109618: CGA-6gch-5439-93qf, CVE-2026-109619: CGA-hhwq-rq33-m2xj}
disclosure: https://www.php.net/archive/2026.php#2026-10-21-5   # 2026-10-21 14:00 UTC
fixed_versions:            # "this version or later"; subpackages (e.g. php-8.4-mbstring) carry the same version
  php-8.2: 8.2.34-r4
  php-8.3: 8.3.35-r4
  php-8.4: 8.4.26-r4
  php-8.5: 8.5.11-r4
  php-8.2-frankenphp: 8.2.34-r3     # frankenphp has its own -rN numbering; -r2/-r3 is correct here
  php-8.3-frankenphp: 8.3.35-r2
  php-8.4-frankenphp: 8.4.26-r2
  php-8.5-frankenphp: 8.5.11-r2
also_fixed_upstream: ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]   # any -rN of these
end_of_life_no_fix: [php-8.1]
sbom_package_regex: '^php-8\.[0-9]+(-frankenphp)?$'
known_affected_images:     # a hint only; always decide from the SBOM
  php: [php, php-fips, php-fpm, frankenphp]
  bundling: [wordpress, drupal, laravel, nextcloud-server, adminer, phpmyadmin, phpmyadmin-fips,
             zabbix, renovate, privatebin-nginx-fpm, privatebin-nginx-fpm-fips, moodle]
public_fallback: "cgr.dev/chainguard/php:{8.2,8.3,8.4,8.5}"   # plain php only, not -fips/frankenphp/bundling images
scanner_feeds:
  - https://packages.cgr.dev/chainguard/security.json
  - https://packages.wolfi.dev/os/security.json
signature_verify:
  # TODO(Chainguard, before publishing): paste the official commands from the signature KB
  # (KB section 2.3) for public and org registries. The public command below verified successfully on 2026-10-21.
  public: >-
    cosign verify cgr.dev/chainguard/IMAGE@DIGEST
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
    --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
  org_registry: TODO   # if still TODO: do not guess; ask the user for their verification policy, or stop at step 5
support: https://support.chainguard.dev
status_page: https://status.chainguard.dev
```

## Step 0: Preflight (read-only)

1. Check the tools: `docker` (or `podman`), `cosign`, `jq`, `crane`, `chainctl`; `kubectl` if Kubernetes is
   in scope. Report what's missing; don't install anything without approval.
2. Ask the user, if not already known:
   - their Chainguard organization (`ORG`, as in `cgr.dev/$ORG/...`)
   - which repositories, directories and clusters (kube contexts) are in scope
   - any **mirror or cache registries** that hold copies of Chainguard images (e.g. `registry.corp/cg/...`)
3. Confirm auth without touching credentials: `chainctl auth status`, `kubectl config current-context`.

## Step 1: Inventory every place a Chainguard image or PHP package is used (read-only)

Collect **image references** (`registry/repo:tag` or `@sha256:…`) with the file and line, or workload, where each is used:

```sh
# Repos: manifests, Helm values, Compose, Terraform, CI files, Dockerfiles (add mirror prefixes to the pattern)
grep -rnoE '(cgr\.dev|<mirror-prefix>)/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?' <paths> \
  --include='*.yaml' --include='*.yml' --include='*.json' --include='*.tf' --include='Dockerfile*' --include='*.hcl'

# Dockerfiles that install PHP themselves
grep -rnE 'apk add.*\bphp-8' <paths> --include='Dockerfile*'

# What's actually running (imageID = the digest the node pulled)
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.image}{"\t"}{.imageID}{"\n"}{end}{end}'
```

Deduplicate by image and digest. Don't filter by image name. Bundling images (e.g. WordPress) are
affected even though they're not named "php", so check **every** Chainguard image.

## Step 2: Read the PHP version from each image's SBOM (read-only)

Resolve tags to digests (`crane digest REF`), then read the SBOM attestation for the digest:

```sh
cosign download attestation \
  --predicate-type=https://spdx.dev/Document \
  --platform=linux/amd64 \
  "$REF" \
  | jq -r '.payload' | base64 -d \
  | jq -r '.predicate.packages[] | select(.name | test("^php-8\\.[0-9]+(-frankenphp)?$")) | "\(.name) \(.versionInfo)"' \
  | sort -u
```

- Use the platform each workload actually runs on (`linux/arm64` too, if used).
- For mirrored images, read the attestation from the mirror if it was copied with `cosign copy`. Otherwise
  read it from the matching `cgr.dev` digest.
- No PHP packages means the image is `NOT AFFECTED`. Attestation unreadable means `UNKNOWN` (step 8).
- For `-dev` images you may cross-check with: `docker run --rm --entrypoint apk "$REF" info -v | grep -E '^php-8'`.

## Step 3: Compare versions exactly (read-only)

**Never compare version strings as text** (`-r10` is newer than `-r4`). Use apk's own comparator:

```sh
docker run --rm cgr.dev/chainguard/wolfi-base apk version -t "<installed>" "<fixed>"   # prints <, = or >
```

Classify each package against `fixed_versions` by matching package name (for `php-8.4` use `php-8.4`'s
row, for `php-8.4-frankenphp` use its own row):

| Result | Status |
|---|---|
| `=` or `>` | `PATCHED` |
| `<` | `VULNERABLE` |
| package is `php-8.1` | `END OF LIFE`: no fix exists; recommend upgrading to 8.2+ (8.4/8.5 preferred, since 8.2 reaches EOL on 2026-12-31) |

An image is `VULNERABLE` if **any** PHP package in it is vulnerable.

Show the user the inventory table now (see Report format) before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

First check whether a patched build exists **in the user's registry**: resolve the tag's current digest
and repeat steps 2–3 on it. If it's still vulnerable, go to step 6 for that image.

| How it's referenced | Proposed change |
|---|---|
| By tag (`:8.4`), and the tag now points to a patched digest | Redeploy so nodes pull the new digest (step 7). Rebuild any derived image with `docker build --pull --no-cache`. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror or cache | Propose `cosign copy cgr.dev/$ORG/IMAGE:TAG <mirror>/IMAGE:TAG` (copies signatures and attestations too), then compare digests on both sides. |
| Derived image (`FROM cgr.dev/...`) | Rebuild with `--pull --no-cache`, push, then update references to the new image. |
| Dockerfile with `apk add php-8.x…` | Raise or remove old pins and fail closed with `apk add --no-cache 'php-8.4>=8.4.26-r4'`. Upgrade every installed `php-8.4-*` extension too. Rebuild with `--pull --no-cache`. If a Chainguard Repository **cooldown** blocks the new versions, tell the user that an org Owner can override it in a custom policy; don't change policy yourself. |
| Custom Assembly image | These rebuild automatically unless the configuration pins PHP package versions. Ask the user to check (or show you) the configuration in the Chainguard Console; propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| `php-8.1` | No fix exists. Propose an upgrade plan to 8.2+ and don't change anything automatically. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the
current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block
(substituting `IMAGE@DIGEST`). If the command for the user's registry is `TODO`, or verification fails,
**stop**: don't deploy that image; report it and point the user to Support.

## Step 6: If the fix isn't in the user's registry yet

An earlier Chainguard sync incident delayed some customer registries. Standard PHP images have since
synced everywhere, but some custom and bundling images may lag.

- Report the image, tag and digest as `WAITING ON CHAINGUARD`, and help the user open a Support request at
  https://support.chainguard.dev, including the image, tag, digest and installed PHP version.
- For the **plain** `php` image only, offer `public_fallback` as a temporary option (approval required).
  It doesn't cover php-fips, frankenphp, phpMyAdmin or other bundling images.
- If they can't update yet, point them to the PHP project's announcement (`disclosure`) for partial
  mitigations. Say clearly that these reduce exposure but are not a fix.

## Step 7: Apply approved changes and roll out

- Make only the approved edits. Commit on a branch and open a PR if the repo uses one.
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`). Use
  `kubectl rollout restart` only for tag-referenced workloads, and only with approval.
- Sync mirrors before redeploying anything that pulls from them.

## Step 8: Re-verify and report

1. Re-run the step 1 `kubectl` query and confirm every affected workload now runs a `PATCHED` digest
   (repeat steps 2–3 on the running `imageID`s, not just the manifests).
2. Scanners: Chainguard's feeds list both CVEs as fixed. If a scanner still flags a patched image, refresh
   its database (for grype: `grype db update`) and confirm it reads a feed in `scanner_feeds`.
3. Produce the final report.

### Report format

```
Chainguard PHP CVE-2026-109618 / CVE-2026-109619 — remediation report (<date, UTC>)

| Where used (file:line / ns/workload) | Image reference | Digest | PHP package(s) found | Status | Action taken / proposed |
|---|---|---|---|---|---|
| k8s prod/web-7f9 | cgr.dev/acme/php:8.4 | sha256:… | php-8.4 8.4.26-r3 | VULNERABLE → PATCHED | rollout restart (approved 14:02) |
| deploy/values.yaml:12 | cgr.dev/acme/wordpress@sha256:… | sha256:… | php-8.3 8.3.35-r4 | PATCHED | none |

Summary: N references checked · patched · vulnerable · end of life · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses: `PATCHED`, `VULNERABLE`, `NOT AFFECTED`, `END OF LIFE`, `UNKNOWN`, `WAITING ON CHAINGUARD`.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| Scanner still reports the CVEs on a patched image | Stale scanner DB or wrong feed → refresh, confirm `scanner_feeds`; re-check the version with steps 2–3 |
| Image metadata shows a build time before the disclosure | Expected: Chainguard built the patched images under embargo, before public disclosure |
| `php -v` shows 8.4.26, not 8.4.27 | Expected: the fix is in `8.4.26-r4`. Both it and 8.4.27 are patched |
| frankenphp shows `-r2` or `-r3`, not `-r4` | Expected: frankenphp has its own release numbers (see `fixed_versions`) |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned PHP version in its configuration (step 4) |
| Own build still installs an old PHP | Cached layer or an old `apk add` pin → `--pull --no-cache`, raise the pin |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the PHP package version from step 2,
and this report. Status updates: https://status.chainguard.dev.
