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
  unsupported_streams_note: >-
    Older tags (18.x to 19.2) are still pullable but aren't rebuilt and run unpatched Ruby (for example
    19.2 has ruby-3.3 3.3.12-r8 and 18.6 has ruby-3.2). No fix will ship for them; the fix is upgrading.
  version_package:                 # per GitLab component image: the package whose version IS the GitLab version
    rails_images: "(commercial-)gitlab-rails-(ce|ee)-X.Y"   # webservice, sidekiq, toolbox, geo-logcursor
    workhorse: "gitlab-workhorse-ce-X.Y or commercial-gitlab-workhorse-ee-X.Y"
    gitaly: "gitaly-X.Y"
    registry: "gitlab-container-registry-X.Y"
    others: "gitlab-<component>-X.Y"   # shell, pages, kas, agent, exporter, runner, runner-helper
    fips: "-fips variants insert -fips before the stream, e.g. gitaly-fips-19.3"
  sbom_version_regex: '^(commercial-)?(gitlab|gitaly)(-[a-z]+)*-[0-9]+\.[0-9]+$'   # any stream (18.x, 19.x, 20.x)
  components_with_ruby: [webservice, sidekiq, toolbox, exporter, geo-logcursor, mailroom]   # a hint only; decide from step 2
  components_without_ruby: [gitaly, workhorse, shell, pages, kas, registry, runner]         # a hint only; decide from step 2
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
signature_verify:                  # KB section 2.2, with the org regexp anchored; also used to verify SBOMs in step 2a
  public: >-
    cosign verify
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com
    --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
    cgr.dev/chainguard/IMAGE@DIGEST
  org_registry: >-
    cosign verify
    --certificate-oidc-issuer=https://issuer.enforce.dev
    --certificate-identity-regexp="^https://issuer\.enforce\.dev/(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})$"
    cgr.dev/$ORG/IMAGE@DIGEST       # anchored: cosign otherwise matches the regexp anywhere in the subject
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
3. Confirm auth without touching credentials. `chainctl auth status -o json | jq -e .valid` must print `true`
   before step 2: with an expired session, cosign and crane can hang on the credential helper with no error.
   If it isn't valid, ask the user to log in. Wrap registry calls in `timeout 120` (`gtimeout` on macOS with
   coreutils) where available. Also check `kubectl config current-context` if Kubernetes is in scope.
4. For an org registry, look up the org's two signing identities now (steps 2a and 5 use them). Check both
   as described in step 5 before using them:
   ```sh
   IMAGE_SYNCER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.CATALOG_SYNCER')
   CUSTOM_IMAGE_BUILDER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.APKO_BUILDER')
   ```
5. If a mirror or internal registry only serves plain HTTP (anything other than `localhost`), stop and ask the
   user how they normally reach it. Don't add insecure flags yourself (ground rule 4).

## Step 1: Inventory every place a Chainguard image or Ruby package is used (read-only)

Collect **image references** (`registry/repo:tag` or `@sha256:…`) with the file and line, or workload, where each is used.

**Primary: `chainctl images discover`** (newer chainctl; check with `chainctl images discover --help`). It reads
Helm values as written, including a split `registry`/`repository`/`tag` and a global image registry, plus
Compose, Terraform, Kubernetes manifests and Dockerfiles, and reports file and line:

```sh
chainctl images discover <path> --parent "$ORG" -o json   # --parent is needed if the identity belongs to several orgs
```

**Fallback, and for anything `discover` doesn't cover:** search the files directly.

```sh
# Image references (add your mirror prefixes). The boundary before the hostname skips apk repository URLs
# such as https://apk.cgr.dev/<org>; the match then includes the leading space or quote, which is harmless.
IMG_RE='(^|[^A-Za-z0-9.-])(cgr\.dev|<mirror-prefix>)/[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?'
# ...in manifests, Helm values, Compose, Terraform and CI files
grep -rnoE "$IMG_RE" <paths> --include='*.yaml' --include='*.yml' --include='*.json' --include='*.tf' --include='*.hcl'
# ...and in Dockerfiles/Containerfiles under any capitalization (grep -i does not affect --include, so use find -iname)
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -noHE "$IMG_RE" {} +

# Builds that install Ruby themselves: Dockerfiles, apko configs (YAML with contents.packages, or inline in
# .tf for the apko Terraform provider) and apko lockfiles. Match the package name alone, because `apk add`
# is often continued over several lines; read the surrounding lines to see the full command.
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE '\bruby-[0-9]+\.[0-9]+' {} +
grep -rnE '\bruby-[0-9]+\.[0-9]+' <paths> --include='*.yaml' --include='*.yml' --include='*.lock.json' --include='*.tf'

# Running pods, including init and ephemeral containers (imageID = the digest the node pulled)
kubectl get pods -A -o json | jq -r '.items[] | .metadata as $m
  | ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) + (.status.ephemeralContainerStatuses // []))[]
  | [$m.namespace, $m.name, .image, .imageID] | @tsv'
# Workload specs, which catch Jobs and CronJobs with no live pod (for GitLab: the migrations Job and the
# backup CronJob, both on the toolbox image, which contains Ruby)
kubectl get deploy,sts,ds,job,cronjob -A -o json | jq -r '.items[] | .kind as $k | .metadata as $m
  | (.spec.jobTemplate.spec.template.spec // .spec.template.spec)
  | ((.initContainers // []) + (.containers // []))[] | [$k, $m.namespace, $m.name, .image] | @tsv'
```

Helm values often split an image across `registry`, `repository`, `tag` and `digest` fields, sometimes with a
global registry. When a grep match has no tag or digest, read the neighbouring lines (and any global registry)
and join them into the full reference before step 2. `chainctl images discover` does this for you.

Deduplicate by image and digest. Don't filter by image name. Images that bundle Ruby (fluentd, Renovate,
GitLab's Rails components) are affected even though they're not named "ruby", so check **every** Chainguard image.

## Step 2: Read the Ruby (and GitLab) versions from each image (read-only)

Resolve tags to digests (`crane digest REF`). Then read the packages using the first method that works.

**2a. Signed SBOM attestation (Chainguard-built images).** Resolve the platform digest the workload runs,
check whether an SBOM attestation exists, and read it **only through signature verification**:
`cosign download attestation` doesn't check signatures, and a mirror or registry the user controls could
serve anything. Set `VERIFY_FLAGS` to the issuer and identity flags from `signature_verify` (`public` for
`cgr.dev/chainguard/...`; `org_registry`, with the identities from step 0, for `cgr.dev/$ORG/...`):

```sh
PLAT=linux/amd64   # the platform the workload runs on (linux/arm64 too, if used)
case "$(crane manifest "$REF" | jq -r '.mediaType // empty')" in
  *image.index*|*manifest.list*) PDIG=$(crane digest --platform "$PLAT" "$REF") ;;
  *) PDIG=$(crane digest "$REF") ;;
esac
REPO=$(printf '%s' "$REF" | sed -E 's/@sha256:[a-f0-9]{64}$//; s#^(.*/[^/:]+):[^/]+$#\1#')   # REF without tag or digest
# Example for public images; see the note above for org registries.
VERIFY_FLAGS=(--certificate-oidc-issuer=https://token.actions.githubusercontent.com
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main)
if [ -z "$PDIG" ]; then
  echo "sbom: error (couldn't resolve the image digest; check access and the reference)"
else
  ERR=$(mktemp)
  # cosign versions differ when there's no attestation: v2 exits 0 with no output; v3 exits 1 with "no
  # attestations with predicate type ... found". Treat both as none, and anything else non-zero as an error.
  ATT=$(cosign download attestation --predicate-type=https://spdx.dev/Document "$REPO@$PDIG" 2>"$ERR"); RC=$?
  if [ "$RC" -eq 0 ] && [ -n "$ATT" ]; then
    if SBOM=$(cosign verify-attestation --type spdxjson "${VERIFY_FLAGS[@]}" "$REPO@$PDIG" 2>"$ERR"); then
      echo "sbom: found, verified"
      printf '%s\n' "$SBOM" | jq -r '.payload' | base64 -d | jq -r '"packages: \(.predicate.packages | length)"'
      printf '%s\n' "$SBOM" | jq -r '.payload' | base64 -d \
        | jq -r '.predicate.packages[]
            | select(.name | test("^ruby-[0-9]+\\.[0-9]+$|^(commercial-)?(gitlab|gitaly)(-[a-z]+)*-[0-9]+\\.[0-9]+$|^jruby-[0-9]+\\.[0-9]+$"))
            | "\(.name) \(.versionInfo)"' \
        | sort -u
    else
      echo "sbom: found, NOT verified: $(head -c 300 "$ERR")"
    fi
  elif [ "$RC" -eq 0 ] || grep -q 'no attestations' "$ERR"; then
    echo "sbom: none"
  else
    echo "sbom: error (cosign exit $RC): $(head -c 300 "$ERR")"
  fi
  rm -f "$ERR"
fi
```

- `sbom: found, verified` plus package lines: compare them in step 3.
- `sbom: found, verified`, `packages: N` with N above 0, and no Ruby lines, on a Chainguard-built image: the
  SBOM lists no Ruby, so the image is `NOT AFFECTED` by this CVE (still check a GitLab component's version for
  the release's other CVEs). If `packages:` is 0 or missing, the SBOM wasn't read; use 2b.
- `sbom: found, NOT verified`: **stop** for this image (ground rule 8). Don't mark it `UNKNOWN` and continue
  with 2b; report it and point the user to Support.
- `sbom: error`: cosign couldn't read the image, usually auth, network or a wrong reference. **Stop** for this
  image: ask the user to check access (for example `chainctl auth configure-docker`) and re-run 2a. Don't
  fall back to 2b, which would hit the same problem.
- `sbom: none`: there's no attestation to read. That's normal for images you build yourself. Use 2b.
- For images you build yourself, use 2b even if they carry an SBOM attestation of their own: it may not
  list Ruby that was copied in from a build stage.

For GitLab images, read the GitLab version from the component's own package (`gitlab.version_package`):
`gitlab-rails-*` for the Rails images, `gitaly-X.Y` for gitaly, `gitlab-workhorse-ce-X.Y` or
`commercial-gitlab-workhorse-ee-X.Y` for workhorse, and so on, where `X.Y` is the stream (for example 19.5 or
18.11). The filter above prints every GitLab package with a stream suffix (`gitlab.sbom_version_regex`, which
matches any stream); pick the component's own one. Helper packages (`-base`, `-logger`, `-scripts`) can be on a different
version, and **the image tag can run ahead of the packages** while images update, so use neither.

**2b. The image's filesystem (fallback).** Images you build yourself (derived images, `apk add` builds,
mirrors copied without `cosign copy`) have no Chainguard attestation, so 2a prints `sbom: none`.
Inspect the image's filesystem instead. This doesn't run the image, and works on single- and multi-arch
references. It reports three things: whether there's an apk database, any Ruby packages it lists, and any Ruby
executables or `libruby` files on disk:

```sh
echo "arch: $(crane config --platform "$PLAT" "$REF" | jq -r '.architecture')"   # must match the workload's platform
FS=$(mktemp)    # one export, inspected twice; needs disk space roughly the size of the image
if ! crane export --platform "$PLAT" "$REF" - > "$FS" || [ ! -s "$FS" ]; then
  echo "export: error"   # stop for this image: an empty export would look like "no Ruby"
else
  DB=$(tar -tf "$FS" 2>/dev/null | grep -m1 -xE '(usr/)?lib/apk/db/installed')
  if [ -n "$DB" ]; then
    echo "apk-db: $DB"
    tar -xOf "$FS" "$DB" | awk -F: '/^P:/{p=$2} /^V:/{if (p ~ /^ruby-[0-9]+\.[0-9]+$/ || p ~ /^(commercial-)?(gitlab|gitaly)(-[a-z]+)*-[0-9]+\.[0-9]+$/ || p ~ /^jruby-[0-9]+\.[0-9]+$/) print "package:", p, $2}'
  else
    echo "apk-db: none"
  fi
  # Ruby executables and libruby on disk, whether or not any package owns them (catches Ruby copied in from a
  # build stage; Onigmo is compiled into libruby, so an app can embed it without a ruby executable).
  # Take the last field after removing any symlink target: works with GNU tar and bsdtar (macOS), whose
  # `tar -tv` column layouts differ.
  tar -tvf "$FS" | awk '$1 ~ /^[-l]/ {sub(/ -> .*/, ""); print $NF}' | grep -E '(^|/)(ruby[0-9.]*|libruby\.so[0-9.]*)$' | sed 's/^/ruby-file: /'
fi
rm -f "$FS"
```

This writes the image's whole filesystem to a temporary file, so it's slower and needs disk space for large
images. Use it only when 2a prints `sbom: none`. If `arch` isn't the platform the workload runs on, the image
doesn't have that platform and crane exported a different one: report it and check the reference the
workload actually pulls.

Interpreting the result:
- **`export: error`:** stop for this image and check access, as for `sbom: error`.
- **Ruby packages found:** compare them in step 3.
- **No Ruby package and no `ruby-file`:** `NOT AFFECTED` by this CVE. For a GitLab component without
  Ruby (gitaly, workhorse, shell and so on), still check its GitLab version for the release's other CVEs (step 3b).
- **A `ruby-file` (executable or `libruby`) but no matching package** (with or without an apk database): mark it `UNKNOWN`, never
  `NOT AFFECTED`. A multi-stage build probably copied Ruby in, for example `FROM ruby-dev AS build` then
  `FROM glibc-dynamic` + `COPY --from=build /usr/bin/ruby …`. Distroless Chainguard bases such as
  `glibc-dynamic` and `static` still have an apk database, so an empty package list alone proves nothing.
  To resolve it, find the build stage the binary came from (read the Dockerfile) and check that stage's base
  image **as it was at build time**: if the stage is pinned by digest, check that digest with steps 2–3; with
  a moving tag, the image's `crane config` history or the build logs may show the digest used. Rate it
  `PATCHED` or `VULNERABLE` from that stage's Ruby, and note "copied from build stage <name>" in the report. If you can't establish the
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

**3a. Ruby status**, one per image. Compare each Ruby package against `fixed_versions` by name (for
`ruby-3.3` use `ruby-3.3`'s row), then take the first that applies:

| Ruby status | When |
|---|---|
| `UNKNOWN` | 2a or 2b couldn't be read; a Ruby executable without a package that you couldn't trace to a build stage; or only `jruby` packages |
| `END OF LIFE` | any Ruby package is in `end_of_life_no_fix` (Ruby 3.2 or earlier); no fix exists |
| `VULNERABLE` | any Ruby package compares `<` its fixed version (including copied-in Ruby traced to a vulnerable build stage) |
| `PATCHED` | every Ruby package compares `=` or `>` its fixed version (including copied-in Ruby traced to a patched build stage) |
| `NOT AFFECTED` | no Ruby package and no `ruby-file` |

**Dockerfiles with no built image to inspect:** rate them from their pins and base images. An `apk add` pin
below the fixed version is `VULNERABLE`. Otherwise check each `FROM` image with steps 2–3, and check the image
the Dockerfile produces once it's built.

**apko configs and lockfiles:** the lockfile decides the version, but **only if the build passes
`apko build --lockfile …`**; apko doesn't pick it up on its own, so check the Makefile or CI. Read the locked
version per architecture:

```sh
jq -r '.contents.packages[] | select(.name | test("^ruby-[0-9]+\\.[0-9]+$")) | "\(.name) \(.version) \(.architecture)"' apko.lock.json
```

Any entry below the fixed version is `VULNERABLE` (note "by lock"). Without a lockfile in use, an exact pin
(`ruby-3.3=3.3.12-r9`) below the fixed version is `VULNERABLE` (note "by pin"); a fuzzy pin (`~`) or an
unpinned package resolves at build time, so check the built image.

**3b. GitLab check** (GitLab component images only). Read the version of the component's own package
(`gitlab.version_package`); the stream is the `X.Y` in its name (for example `gitlab-rails-ce-18.11` is stream 18.11). Compare the version (without `-rN`) with the
same comparator:

| GitLab result | When |
|---|---|
| `OK` | the stream is in `gitlab.fixed_versions` and the version is at or above it, or the stream is newer than every listed stream |
| `UPDATE NEEDED` | the stream is listed and the version is below its fixed version |
| `UNSUPPORTED` | the stream is older than every listed stream (Chainguard builds 19.3, 19.4 and 19.5 only) |
| `UNKNOWN` | no version package was found; say so in the report, but it doesn't change the final status |

**3c. Final status: the first row that matches wins.**

| # | Ruby status | GitLab result | Final status |
|---|---|---|---|
| 1 | `UNKNOWN` | any | `UNKNOWN` |
| 2 | any other | `UNSUPPORTED` | `UNSUPPORTED STREAM`: no fix will ship for it (`gitlab.unsupported_streams_note`); recommend 19.3.6, 19.4.3 or 19.5.1 or later, and note the Ruby status in the Action column |
| 3 | `END OF LIFE` | any | `END OF LIFE` |
| 4 | `VULNERABLE` | any | `VULNERABLE` |
| 5 | `PATCHED` | `UPDATE NEEDED` | `PATCHED, GITLAB UPDATE NEEDED`: safe from CVE-2026-110264, not from the release's other CVEs |
| 6 | `NOT AFFECTED` | `UPDATE NEEDED` | `NOT AFFECTED, GITLAB UPDATE NEEDED`: for GitLab's other CVEs only |
| 7 | `PATCHED` | `OK`, `UNKNOWN` or not GitLab | `PATCHED` |
| 8 | `NOT AFFECTED` | `OK`, `UNKNOWN` or not GitLab | `NOT AFFECTED` |

After step 4, a `VULNERABLE` Chainguard-built image whose fix isn't in the user's registry yet becomes
`WAITING ON CHAINGUARD`.

Show the user the inventory table now (see Report format) before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

An `UNSUPPORTED STREAM` image goes straight to the upgrade plan (row below). Don't look for a patched build or
send it to Support: none will come.

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
| By tag (`:19.5`), and the tag now points to a patched digest | Propose pinning the reference to the digest you verified in steps 2–3 and 5 (`IMAGE:TAG@sha256:…`), then roll out (step 7). A restart alone can reuse a cached image (`imagePullPolicy: IfNotPresent`), and the tag can move after you verified it. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror | Propose copying the **verified digest**, not the tag (which can move): `cosign copy cgr.dev/$ORG/IMAGE@sha256:<verified> <mirror>/IMAGE:TAG`. This copies signatures and attestations too. Then compare digests on both sides. |
| Via a pull-through cache (Artifactory remote repo, Harbor proxy cache) | These can't receive a push. Propose refreshing or expiring the cached tag, or referencing the verified digest, which the cache will fetch. |
| Derived image (`FROM cgr.dev/...`) | If the `FROM` line is pinned by digest, first propose bumping it to a verified, patched digest (show the diff): rebuilding a pinned base rebuilds the same vulnerable image. Then rebuild with `--pull --no-cache`, push, and update references to the new image. Verify the rebuilt image with steps 2–3: it has no Chainguard attestation, so step 2b applies. |
| Dockerfile with `apk add ruby-3.x…` | Raise or remove old pins and fail closed, for example `apk add --no-cache 'ruby-3.3>=3.3.12-r10'`. Upgrade every installed `ruby-3.3-*` subpackage too. Rebuild with `--pull --no-cache`, then verify the result with steps 2b–3. If a policy blocks the new versions, tell the user to contact their org admin or Support; don't change policy yourself. |
| apko config or lockfile | Raise or remove the YAML pin (or use `ruby-3.3>=3.3.12-r10`), then regenerate the lockfile with `apko lock`. That moves **every** package to its newest version, so show the user the whole lockfile diff for approval, not just the Ruby lines. Rebuild, then verify with steps 2b–3. |
| Custom Assembly image | These rebuild automatically unless the configuration pins Ruby package versions. If your chainctl has it, read the pins with `chainctl images overlays list --parent "$ORG" -o json` (packages under `.overlays[].config.contents.packages`, repos under `.bindings[]`; check the output's shape before relying on it). Otherwise ask the user to check the configuration in the Chainguard Console. Propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| GitLab stream older than 19.3 | Propose an upgrade plan to 19.3.6, 19.4.3 or 19.5.1 or later, following GitLab's upgrade path. Don't change anything automatically. |
| Ruby 3.2 or earlier | No fix exists. Propose moving to an image or tag that runs Ruby 3.3 or later. Don't change anything automatically. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the
current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block,
substituting `IMAGE@DIGEST`. Use `public` for `cgr.dev/chainguard/...` and `org_registry` for `cgr.dev/$ORG/...`.
Images the user builds themselves aren't signed by Chainguard; verify them with the user's own signing policy, if any.
For a mirror, verify the `cgr.dev` digest you copied from, or the mirror copy if it was made with `cosign copy`.

For the org registry, use the org's two signing identities from step 0.

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
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`), with the references
  pinned to verified digests. Don't rely on `kubectl rollout restart` for tag references: nodes that cached
  the tag keep running the old image.
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

| Where used (file:line / ns/workload) | Image reference | Digest | Ruby package(s) | GitLab version (package) | Status | Action taken / proposed |
|---|---|---|---|---|---|---|
| k8s gitlab/webservice-7f9 | cgr.dev/acme/gitlab-webservice-ce:19.5 | sha256:… | ruby-3.3 3.3.12-r9 | gitlab-rails-ce-19.5 19.5.1-r0 | VULNERABLE → PATCHED | rollout restart (approved 14:02) |
| k8s logging/fluentd-x2 | cgr.dev/acme/fluentd:latest | sha256:… | ruby-3.4 3.4.11-r6 | n/a | PATCHED | none |
| k8s gitlab/gitaly-0 | cgr.dev/acme/gitaly:19.3 | sha256:… | none | gitaly-19.3 19.3.5-r2 | NOT AFFECTED, GITLAB UPDATE NEEDED | pull the 19.3.6 build (proposed) |

Summary: N references checked · patched · patched, GitLab update needed · not affected · not affected, GitLab update needed · vulnerable · end of life · unsupported stream · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses (from step 3c, plus step 4's `WAITING ON CHAINGUARD`): `PATCHED`, `PATCHED, GITLAB UPDATE NEEDED`,
`NOT AFFECTED`, `NOT AFFECTED, GITLAB UPDATE NEEDED`, `VULNERABLE`, `END OF LIFE`, `UNSUPPORTED STREAM`,
`UNKNOWN`, `WAITING ON CHAINGUARD`. Put the reason in the Action column (for example "pin in svc/Dockerfile:4"
or "Ruby copied from build stage `build`"), not in the status.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| Scanner says the GitLab image is fixed, but Ruby is older than the fixed version | Scanners match this CVE on the GitLab version → the image isn't protected until its Ruby package is patched (steps 2–3) |
| Scanner doesn't flag a Ruby image at all | Expected: Ruby has no CVE for this bug → check the Ruby package version (steps 2–3) |
| GitLab image has the fixed Ruby but an older gitlab-rails | `PATCHED, GITLAB UPDATE NEEDED` → update to 19.3.6, 19.4.3 or 19.5.1 or later for the release's other CVEs |
| GitLab image tag says 19.5.1, but gitlab-rails is older | The tag ran ahead of the Rails package while images updated → pull again later and re-check gitlab-rails |
| `ruby -v` shows 3.3.12, not a newer Ruby | Expected: the fix is in the `-r10` package, which keeps the 3.3.12 version number |
| Upstream Ruby 4.0.8 is out; is that the fix? | No: upstream 4.0.8 doesn't include it. Chainguard's ruby-4.0 packages carry the fix, including 4.0.8-r0 |
| gitaly or workhorse image has no ruby package | Expected: those images don't contain Ruby, so they're not affected by this CVE. Check their own package (`gitaly-X.Y`, `gitlab-workhorse-*-X.Y`) for the GitLab version (step 3b) |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, a cached tag (`imagePullPolicy: IfNotPresent`), or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned Ruby version in its configuration (step 4) |
| Own build still installs an old Ruby | Cached layer or an old `apk add` pin → `--pull --no-cache`, raise the pin |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the Ruby (and gitlab-rails) package
versions from step 2, and this report. Status updates: https://status.chainguard.dev.
