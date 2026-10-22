---
name: gitlab-onigmo
description: >-
  Find, verify and remediate Chainguard images and packages affected by
  CVE-2026-110264 (critical GitLab RCE, CVSS 10.0) in this environment. The
  root cause is Onigmo, the regular expression engine built into Ruby, so the
  fix is in Chainguard's Ruby packages, not only the GitLab version.
  Inventories image references in repos and running Kubernetes workloads,
  checks each image's SBOM for the Ruby package (and, for GitLab, the
  gitlab-rails package), proposes and (with approval) applies fixes for tag,
  digest-pinned, mirrored, Custom Assembly and apk-add builds, then
  re-verifies. Use when the user mentions CVE-2026-110264, Onigmo, Chainguard's
  GitLab or Ruby advisory, or asks "are we patched?".
---

# Remediate CVE-2026-110264 in Chainguard GitLab and Ruby images

Published by Chainguard for its customers. This skill implements the steps in Chainguard's KB article
*"ACTION REQUIRED: Update Chainguard GitLab and Ruby images for CVE-2026-110264"* so an agent can carry
them out in your environment. The human-readable KB remains the authority: if anything here disagrees
with it, follow the KB and tell the user.

Two facts shape everything below:

- **The fix is in Ruby.** CVE-2026-110264 is assigned to GitLab, but the bug is in Onigmo, the regex
  engine built into Ruby. GitLab's own packages bundle a patched Ruby. Chainguard images run GitLab on
  Chainguard's separately packaged Ruby, so what protects an image is its **Ruby package version**.
- **Scanners can't confirm it.** Ruby has no CVE or advisory for this bug, so scanners don't match it on
  the Ruby package, and Ruby images other than GitLab aren't flagged at all. Decide from the package
  versions in steps 2 and 3, never from scanner output.

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
7. **Never try to trigger the bug.** Don't run crafted regular expressions or exploit code against any
   image or service to "test" it. Verification is by package version only.
8. **Stop and escalate** if a patched version isn't available in the user's registry (step 6), or a
   signature fails to verify.

## Incident data (single source of truth: update this block for later rounds)

```yaml
cves: [CVE-2026-110264]
assigned_by: GitLab                # root cause: Onigmo (Ruby's regex engine); Ruby has no CVE or advisory for it
disclosure: https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/   # 2026-10-21
fixed_versions:                    # Ruby packages, "this version or later"; later revisions keep the fix
  ruby-3.3: 3.3.12-r10
  ruby-3.4: 3.4.11-r5
  ruby-4.0: 4.0.7-r6               # ruby-4.0 4.0.8-r0 and later also carry the fix
upstream_ruby_releases_without_fix: ["4.0.8"]   # upstream Ruby 4.0.8 does NOT include it; Chainguard's 4.0.8 package does
end_of_life_no_fix: [ruby-3.2, ruby-3.1, ruby-3.0]
sbom_ruby_regex: '^ruby-[0-9]+\.[0-9]+$'
gitlab:
  fixed_versions: ["19.3.6", "19.4.3", "19.5.1"]   # also fix 11 other CVEs in GitLab's release
  supported_streams: ["19.3", "19.4", "19.5"]      # Chainguard GitLab images are built for these only
  sbom_rails_regex: '^(commercial-)?gitlab-rails-(ce|ee)(-fips)?-[0-9]+\.[0-9]+$'   # its version is the GitLab version
  components_with_ruby: [webservice, sidekiq, toolbox, exporter, geo-logcursor, mailroom]
  components_without_ruby: [gitaly, workhorse, shell, pages, kas, registry, runner]   # not affected by this CVE
known_affected_images:             # a hint only; always decide from the SBOM
  gitlab: [gitlab-webservice-ce, gitlab-sidekiq-ce, gitlab-toolbox-ce, gitlab-exporter, gitlab-mailroom,
           commercial-gitlab-webservice-ee, commercial-gitlab-sidekiq-ee, commercial-gitlab-toolbox-ee,
           commercial-gitlab-geo-logcursor-ee]          # and their -fips variants
  bundling: [ruby, rails, fluentd, fluentd-kubernetes-daemonset, fluent-operator-fluentd,
             kube-logging-operator-fluentd, kube-fluentd-operator, fluentd-iamguarded, fluent-bit-watcher,
             renovate, pact-broker, pghero, cinc-auditor]   # and their -fips variants
not_onigmo: [jruby]                # JRuby uses a different regex engine; report UNKNOWN and confirm with Support
scanner_feeds:
  - https://packages.cgr.dev/chainguard/security.json
  - https://packages.wolfi.dev/os/security.json
gitlab_detections:                 # GitLab's threat detections for self-managed instances (watch only, not a fix)
  - https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/Detections/platforms/GitLab/Vulnerability%20Detections/onigmo_native_worker_crash.md
  - https://gitlab.com/gitlab-security-oss/tldr/-/blob/main/Detections/platforms/GitLab/Vulnerability%20Detections/org_mode_render_error_burst.md
signature_verify:                  # from the KB, section 2.2 ("Verify the signature"); see step 5 for how to run them
  public: >-
    cosign verify
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
    --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
    cgr.dev/chainguard/IMAGE@DIGEST
  org_registry: >-
    cosign verify
    --certificate-oidc-issuer=https://issuer.enforce.dev
    --certificate-identity-regexp="https://issuer.enforce.dev/(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})"
    cgr.dev/$ORG/IMAGE@DIGEST
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
4. If a mirror or internal registry only serves plain HTTP (anything other than `localhost`), stop and ask the
   user how they normally reach it. Don't add insecure flags yourself (ground rule 4).

## Step 1: Inventory every place a Chainguard image or Ruby package is used (read-only)

Collect **image references** (`registry/repo:tag` or `@sha256:…`) with the file and line, or workload, where each is used:

```sh
# Image references (add your mirror prefixes to the pattern)
IMG_RE='(cgr\.dev|<mirror-prefix>)/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?'
# ...in manifests, Helm values, Compose, Terraform and CI files
grep -rnoE "$IMG_RE" <paths> --include='*.yaml' --include='*.yml' --include='*.json' --include='*.tf' --include='*.hcl'
# ...and in Dockerfiles/Containerfiles under any capitalization (grep -i does not affect --include, so use find -iname)
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -noHE "$IMG_RE" {} +

# Dockerfiles that install Ruby themselves. Match the package name alone, because `apk add` is often
# continued over several lines; read the surrounding lines to see the full command.
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE '\bruby-[0-9]+\.[0-9]+' {} +

# What's actually running (imageID = the digest the node pulled)
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.image}{"\t"}{.imageID}{"\n"}{end}{end}'
```

Helm values often split an image across `registry`, `repository`, `tag` and `digest` fields. When a match
has no tag or digest, read the neighbouring lines and join them into the full reference before step 2.

Deduplicate by image and digest. Don't filter by image name. Images that bundle Ruby (fluentd, Renovate,
GitLab's Rails components) are affected even though they're not named "ruby", so check **every** Chainguard image.

## Step 2: Read the Ruby (and GitLab) versions from each image (read-only)

Resolve tags to digests (`crane digest REF`). Then read the packages using the first method that works.

**2a. SBOM attestation (Chainguard-built images).** Pass `--platform` only when the reference is a
multi-arch index; cosign rejects it on a single-arch image ("specified reference is not a multiarch image"):

```sh
PLAT=linux/amd64   # the platform the workload runs on (linux/arm64 too, if used)
case "$(crane manifest "$REF" | jq -r '.mediaType // empty')" in
  *image.index*|*manifest.list*) PLAT_FLAG="--platform=$PLAT" ;;
  *) PLAT_FLAG="" ;;
esac
# cosign exits 0 with no output when an image has no attestation, so check for output explicitly:
# an empty result is NOT the same as "no Ruby".
ATT=$(cosign download attestation --predicate-type=https://spdx.dev/Document $PLAT_FLAG "$REF")
if [ -z "$ATT" ]; then
  echo "sbom: none"
else
  echo "sbom: found"
  printf '%s\n' "$ATT" | jq -r '.payload' | base64 -d | jq -r '"packages: \(.predicate.packages | length)"'
  printf '%s\n' "$ATT" | jq -r '.payload' | base64 -d \
    | jq -r '.predicate.packages[]
        | select(.name | test("^ruby-[0-9]+\\.[0-9]+$|^(commercial-)?gitlab-rails-(ce|ee)(-fips)?-[0-9]+\\.[0-9]+$|^jruby"))
        | "\(.name) \(.versionInfo)"' \
    | sort -u
fi
```

- `sbom: found` plus package lines: compare them in step 3.
- `sbom: found`, `packages: N` with N above 0, and no Ruby lines, on a Chainguard-built image: the SBOM lists
  no Ruby, so the image is `NOT AFFECTED` by this CVE (still check a GitLab component's version for the
  release's other CVEs). If `packages:` is 0 or missing, the SBOM wasn't read; use 2b.
- `sbom: none`: there's no attestation to read. That's normal for images you build yourself. Use 2b.
- For images you build yourself, use 2b even if they carry an SBOM attestation of their own: it may not
  list Ruby that was copied in from a build stage.

For GitLab images, the `gitlab-rails` package version is the GitLab version. **Don't trust the image tag
for it**: while images update, a tag can show the new GitLab version before the Rails package catches up.
Only images that run Rails have a `gitlab-rails` package; gitaly, workhorse and the other Go components don't.

**2b. The image's filesystem (fallback).** Images you build yourself (derived images, `apk add` builds,
mirrors copied without `cosign copy`) have no Chainguard attestation, so 2a prints `sbom: none`.
Inspect the image's filesystem instead. This doesn't run the image, and works on single- and multi-arch
references. It reports three things: whether there's an apk database, any Ruby packages it lists, and any Ruby
executables on disk:

```sh
echo "arch: $(crane config --platform "$PLAT" "$REF" | jq -r '.architecture')"   # must match the workload's platform
FS=$(mktemp)    # one export, inspected twice; needs disk space roughly the size of the image
crane export --platform "$PLAT" "$REF" - > "$FS"
DB=$(tar -tf "$FS" | grep -m1 -xE '(usr/)?lib/apk/db/installed')
if [ -n "$DB" ]; then
  echo "apk-db: $DB"
  tar -xOf "$FS" "$DB" | awk -F: '/^P:/{p=$2} /^V:/{if (p ~ /^ruby-[0-9]+\.[0-9]+$/ || p ~ /^(commercial-)?gitlab-rails-(ce|ee)(-fips)?-[0-9]+\.[0-9]+$/ || p ~ /^jruby/) print "package:", p, $2}'
else
  echo "apk-db: none"
fi
# Ruby executables on disk, whether or not any package owns them (catches Ruby copied in from a build stage).
# Take the last field after removing any symlink target: works with GNU tar and bsdtar (macOS), whose
# `tar -tv` column layouts differ.
tar -tvf "$FS" | awk '$1 ~ /^[-l]/ {sub(/ -> .*/, ""); print $NF}' | grep -E '(^|/)ruby[0-9.]*$' | sed 's/^/executable: /'
rm -f "$FS"
```

This writes the image's whole filesystem to a temporary file, so it's slower and needs disk space for large
images. Use it only when 2a prints `sbom: none`. If `arch` isn't the platform the workload runs on, the image
doesn't have that platform and crane exported a different one: report it and check the reference the
workload actually pulls.

Interpreting the result:
- **Ruby packages found:** compare them in step 3.
- **No Ruby package and no Ruby executable:** `NOT AFFECTED` by this CVE. For a GitLab component without
  Ruby (gitaly, workhorse, shell and so on), still check its GitLab version for the release's other CVEs (step 3).
- **A Ruby executable but no matching package** (with or without an apk database): mark it `UNKNOWN`, never
  `NOT AFFECTED`. A multi-stage build probably copied Ruby in, for example `FROM ruby-dev AS build` then
  `FROM glibc-dynamic` + `COPY --from=build /usr/bin/ruby …`. Distroless Chainguard bases such as
  `glibc-dynamic` and `static` still have an apk database, so an empty package list alone proves nothing.
  To resolve it, find the build stage the binary came from (read the Dockerfile) and check that stage's base
  image **as it was at build time**: if the stage is pinned by digest, check that digest with steps 2–3; with
  a moving tag, the image's `crane config` history or the build logs may show the digest used. Report
  `PATCHED (copied from <stage>)` or `VULNERABLE (copied from <stage>)`. If you can't establish the
  build-time base, keep it `UNKNOWN` and recommend rebuilding with `--pull --no-cache` with the build stage
  pinned by a verified digest.
- **Only `jruby` packages:** mark `UNKNOWN` (JRuby uses a different regex engine) and confirm with Support.
- For mirrored images, read from the mirror. If the mirror has no attestation, 2b on the mirror is the
  authoritative check of what you actually run.

## Step 3: Compare versions exactly (read-only)

**Never compare version strings as text** (`-r10` is newer than `-r9`). Use apk's own comparator:

```sh
docker run --rm cgr.dev/chainguard/wolfi-base apk version -t "<installed>" "<fixed>"   # prints <, = or >
```

Classify each Ruby package against `fixed_versions` by matching package name (for `ruby-3.3` use `ruby-3.3`'s row):

| Result | Status |
|---|---|
| `=` or `>` | `PATCHED` |
| `<` | `VULNERABLE` |
| package is in `end_of_life_no_fix` (Ruby 3.2 or earlier) | `END OF LIFE`: no fix exists; recommend moving to an image or tag that runs Ruby 3.3 or later |

An image is `VULNERABLE` if **any** Ruby package in it is vulnerable.

**Dockerfiles with no built image to inspect:** rate them from their pins and base images. An `apk add` pin
below the fixed version is `VULNERABLE (by pin)`. Otherwise check each `FROM` image with steps 2–3, and
check the image the Dockerfile produces once it's built.

Then, for GitLab images, check the `gitlab-rails` version against `gitlab.fixed_versions` for its stream
(19.3 needs 19.3.6, and so on), using the same comparator on the version without its `-rN`:

| Ruby result | GitLab result | Status |
|---|---|---|
| `PATCHED` | at or above the fixed version | `PATCHED` |
| `PATCHED` | below the fixed version | `PATCHED, GITLAB UPDATE NEEDED`: safe from CVE-2026-110264, but not from the release's other CVEs |
| `VULNERABLE` | any | `VULNERABLE` |
| stream older than 19.3 | any | `UNSUPPORTED STREAM`: Chainguard builds 19.3, 19.4 and 19.5 only; recommend 19.3.6, 19.4.3 or 19.5.1 or later |

Show the user the inventory table now (see Report format) before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

For **images Chainguard builds** (catalog, Custom Assembly and custom images), first check whether a patched
build exists **in the user's registry**: resolve the tag's current digest and repeat steps 2–3 on it. If it's
still vulnerable, go to step 6 for that image. To list newer builds of a tag in an org registry:
`chainctl images history IMAGE:TAG --parent $ORG`. For **images the user builds**, the fix is a rebuild
(rows below), not Support.

To tell a mirror copy from the user's own build: a mirror copy has the same digest as the image in
`cgr.dev/$ORG` (compare `crane digest` on both); the user's own build has a different digest, and its
`crane config` history shows their build steps.

| How it's referenced | Proposed change |
|---|---|
| By tag (`:19.5`), and the tag now points to a patched digest | Redeploy so nodes pull the new digest (step 7). Rebuild any derived image with `docker build --pull --no-cache`. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror or cache | Propose `cosign copy cgr.dev/$ORG/IMAGE:TAG <mirror>/IMAGE:TAG` (copies signatures and attestations too), then compare digests on both sides. |
| Derived image (`FROM cgr.dev/...`) | Rebuild with `--pull --no-cache`, push, then update references to the new image. Verify the rebuilt image with steps 2–3: it has no Chainguard attestation, so step 2b applies. |
| Dockerfile with `apk add ruby-3.x…` | Raise or remove old pins and fail closed, for example `apk add --no-cache 'ruby-3.3>=3.3.12-r10'`. Upgrade every installed `ruby-3.3-*` subpackage too. Rebuild with `--pull --no-cache`, then verify the result with steps 2b–3. If a policy blocks the new versions, tell the user to contact their org admin or Support; don't change policy yourself. |
| Custom Assembly image | These rebuild automatically unless the configuration pins Ruby package versions. Ask the user to check (or show you) the configuration in the Chainguard Console; propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| GitLab stream older than 19.3 | Propose an upgrade plan to 19.3.6, 19.4.3 or 19.5.1 or later, following GitLab's upgrade path. Don't change anything automatically. |
| Ruby 3.2 or earlier | No fix exists. Propose moving to an image or tag that runs Ruby 3.3 or later. Don't change anything automatically. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the
current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block,
substituting `IMAGE@DIGEST`. Use `public` for `cgr.dev/chainguard/...` and `org_registry` for `cgr.dev/$ORG/...`.
Images the user builds themselves aren't signed by Chainguard; verify them with the user's own signing policy, if any.
For a mirror, verify the `cgr.dev` digest you copied from, or the mirror copy if it was made with `cosign copy`.

For the org registry, first look up the org's two signing identities:

```sh
IMAGE_SYNCER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.CATALOG_SYNCER')
CUSTOM_IMAGE_BUILDER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.APKO_BUILDER')
```

**Check both values before running cosign.** Each must be a non-empty identity of the form
`<hex>/<hex>`, not empty and not `null`. cosign matches `--certificate-identity-regexp` anywhere in the
certificate subject, so an empty alternative in `(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})` would accept a
signature from *any* `issuer.enforce.dev` identity. If one value is missing, drop it from the group (for example
`(${IMAGE_SYNCER})`). If both are missing, stop: report it, and point the user to Support.

If verification fails for an image, **stop**: don't deploy that image; report it and point the user to Support.
Never retry with a looser identity or issuer.

## Step 6: If the fix isn't in the user's registry yet

Patched images reach customer registries automatically, usually within an hour of being published.

- Report the image, tag and digest as `WAITING ON CHAINGUARD`, and help the user open a Support request at
  https://support.chainguard.dev, including the image, tag, digest and installed Ruby (and gitlab-rails) version.
- Don't switch the user to public images or another registry as a workaround; that's a Support decision.
- If they can't update GitLab yet, point them to GitLab's threat detections (`gitlab_detections`) to watch
  for exploitation attempts. Say clearly that these detect, but don't prevent, exploitation.

## Step 7: Apply approved changes and roll out

- Make only the approved edits. Commit on a branch and open a PR if the repo uses one.
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`). Use
  `kubectl rollout restart` only for tag-referenced workloads, and only with approval.
- Sync mirrors before redeploying anything that pulls from them.

## Step 8: Re-verify and report

1. Re-run the step 1 `kubectl` query and confirm every affected workload now runs a `PATCHED` digest
   (repeat steps 2–3 on the running `imageID`s, not just the manifests).
2. Scanners: don't use scanner output as confirmation for this CVE. It's assigned to GitLab and Ruby has no
   CVE for it, so scanners can't match it on the Ruby package. Steps 2–3 are the confirmation.
3. Produce the final report.

### Report format

```
Chainguard CVE-2026-110264 (GitLab / Ruby Onigmo) — remediation report (<date, UTC>)

| Where used (file:line / ns/workload) | Image reference | Digest | Ruby package(s) | gitlab-rails | Status | Action taken / proposed |
|---|---|---|---|---|---|---|
| k8s gitlab/webservice-7f9 | cgr.dev/acme/gitlab-webservice-ce:19.5 | sha256:… | ruby-3.3 3.3.12-r9 | 19.5.1-r0 | VULNERABLE → PATCHED | rollout restart (approved 14:02) |
| k8s logging/fluentd-x2 | cgr.dev/acme/fluentd:latest | sha256:… | ruby-3.4 3.4.11-r6 | n/a | PATCHED | none |
| k8s gitlab/gitaly-0 | cgr.dev/acme/gitaly:19.3 | sha256:… | none | n/a | NOT AFFECTED (check GitLab version) | none |

Summary: N references checked · patched · patched, GitLab update needed · vulnerable · not affected · end of life · unsupported stream · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses: `PATCHED`, `PATCHED, GITLAB UPDATE NEEDED`, `VULNERABLE`, `NOT AFFECTED`, `END OF LIFE`,
`UNSUPPORTED STREAM`, `UNKNOWN`, `WAITING ON CHAINGUARD`.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| Scanner says the GitLab image is fixed, but Ruby is older than the fixed version | Scanners match this CVE on the GitLab version → the image isn't protected until its Ruby package is patched (steps 2–3) |
| Scanner doesn't flag a Ruby image at all | Expected: Ruby has no CVE for this bug → check the Ruby package version (steps 2–3) |
| GitLab image has the fixed Ruby but an older gitlab-rails | `PATCHED, GITLAB UPDATE NEEDED` → update to 19.3.6, 19.4.3 or 19.5.1 or later for the release's other CVEs |
| GitLab image tag says 19.5.1, but gitlab-rails is older | The tag ran ahead of the Rails package while images updated → pull again later and re-check gitlab-rails |
| `ruby -v` shows 3.3.12, not a newer Ruby | Expected: the fix is in the `-r10` package, which keeps the 3.3.12 version number |
| Upstream Ruby 4.0.8 is out; is that the fix? | No: upstream 4.0.8 doesn't include it. Chainguard's ruby-4.0 packages carry the fix, including 4.0.8-r0 |
| gitaly or workhorse image has no ruby package | Expected: those images don't contain Ruby and aren't affected by this CVE; still update them for GitLab's other CVEs |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned Ruby version in its configuration (step 4) |
| Own build still installs an old Ruby | Cached layer or an old `apk add` pin → `--pull --no-cache`, raise the pin |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the Ruby (and gitlab-rails) package
versions from step 2, and this report. Status updates: https://status.chainguard.dev.
