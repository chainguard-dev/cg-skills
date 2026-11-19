---
name: nginx2root
description: >-
  Find, verify and remediate Chainguard images and packages affected by
  NGINX2Root, the five unauthenticated NGINX vulnerabilities disclosed on
  2026-11-18 (CVE-2026-123633, CVE-2026-123007, CVE-2026-123634,
  CVE-2026-121810, CVE-2026-113425). Covers nginx, NGINX Plus and the packages
  that bundle their own NGINX (OpenResty, Apache APISIX, Kong,
  ingress-nginx-controller, Angie), images you build yourself, and the
  configuration each CVE needs. Inventories image references in repos and
  running Kubernetes workloads, reads each image's SBOM and filesystem for
  NGINX, checks exposure in the NGINX configuration, proposes and (with
  approval) applies fixes, then re-verifies. Use when the user mentions
  NGINX2Root, any of these CVEs, Chainguard's NGINX advisory, or asks "are we
  patched?".
---

# Remediate NGINX2Root (CVE-2026-123633, CVE-2026-123007, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425) in Chainguard images

Published by Chainguard for its customers. This skill implements the steps in Chainguard's KB article *"[ACTION REQUIRED] NGINX security updates (NGINX2Root): update Chainguard images that include NGINX"* so an agent can carry them out in your environment. The human-readable KB remains the authority: if anything here disagrees with it, follow the KB and tell the user.

Three facts shape everything below:

- **Decide from the package version and revision, never from the NGINX version string.** Several packages carry the fixes as backported patches, so `nginx -v` and the `Server:` header keep showing the old version on fixed builds: ingress-nginx-controller reports 1.27.1, Kong 1.25.3, OpenResty and Apache APISIX 1.31.8.1, NGINX Plus 1.31.8 (r37.3.0). OpenResty's fix is only in the `-r1` revision.
- **NGINX hides inside other packages.** OpenResty, Apache APISIX, Kong, ingress-nginx-controller, Angie and fabiocicerchia-nginx-lua each carry their own NGINX, and images you build yourself may copy one in. Step 2 finds them from the SBOM and the filesystem.
- **Exposure depends on configuration; the fix doesn't.** Each CVE needs a feature to be on (HTTP/2, a resolver, HTTP/3, the mail proxy). Step 3b reports exposure so the user can prioritise and choose stopgaps, but an unexposed image on a vulnerable build is still `VULNERABLE`: the only complete fix is the update.

## Ground rules for the agent (read first, follow always)

1. **Discovery and verification are read-only.** Run them freely.
2. **Every change needs the user's explicit approval first**: editing files, pushing or copying images, building, deploying, restarting workloads, changing NGINX configuration or policies. Show the exact diff or command, say what it affects, and wait for a yes. Approval for one change does not carry over to the next.
3. **Prefer the user's own change process.** If manifests live in Git (GitOps, Helm, Terraform), propose a branch or PR instead of changing a cluster directly. Ask before touching production.
4. **Never weaken security to make progress.** No skipping signature verification, no `--insecure` or `--allow-insecure-registry`, no disabling admission policies, no pinning *older* versions.
5. **Don't handle credentials.** If a registry, cluster or `chainctl` isn't authenticated, ask the user to log in themselves. Never print tokens or secrets.
6. **Report uncertainty instead of guessing.** If an image's SBOM or filesystem can't be read, mark it `UNKNOWN`, never "patched".
7. **Never try to trigger the bugs.** Don't send crafted requests or run exploit code against any image or service to "test" it. Verification is by version; exposure is by reading configuration.
8. **Stop and escalate** if a patched version isn't available in the user's registry (step 6), or a signature fails to verify.

## Incident data (single source of truth: update this block for later rounds)

```yaml
disclosed: 2026-11-18                # upstream fixes: NGINX 1.31.9 (mainline), 1.30.7 (stable), NGINX Plus 37.3.0.1
disclosure: https://nginx.org/en/security_advisories.html
cves:                                # F5 scores all five CVSS 4.0 9.2 (CVSS 3.1 8.1); none needs authentication
  CVE-2026-123633: {area: HTTP/2, needs: "HTTP/2 on a listener, and requests proxied with proxy_pass, grpc_pass, fastcgi_pass, uwsgi_pass or scgi_pass"}
  CVE-2026-123007: {area: HTTP/2, needs: "HTTP/2 on any reachable listener, TLS or cleartext; no upstream needed. Public proof-of-concept exists"}
  CVE-2026-123634: {area: resolver, needs: "a resolver, a proxied target with a variable that evaluates to a hostname, and an overlapping lookup in the same request (SSI, mirror, the addition module, or njs r.subrequest()); HTTP/2 not required"}
  CVE-2026-121810: {area: HTTP/3, needs: "NGINX built with HTTP/3, and a listen ... quic listener"}
  CVE-2026-113425: {area: mail, needs: "the mail module compiled in or loaded, and a mail {} block with a listening server"}
advisories:                          # CVE -> CGA ID and GHSA (Chainguard advisory data, shared by every package's record)
  CVE-2026-123633: {cga: CGA-2vq5-j7gf-qpj9, ghsa: GHSA-7xxj-p8w5-434q}
  CVE-2026-123007: {cga: CGA-6rrq-66xf-37vx, ghsa: GHSA-m4q8-cf44-f42r}
  CVE-2026-123634: {cga: CGA-5r3f-c3gc-m3qg, ghsa: GHSA-qxf8-26hv-4jh5}
  CVE-2026-121810: {cga: CGA-342v-w252-h92m, ghsa: GHSA-fxx2-rrmx-x4v2}
  CVE-2026-113425: {cga: CGA-37gx-mq9w-vgfv, ghsa: GHSA-rmpv-v5m5-rr27}
fixed_versions:                      # apk origin package -> first build with every applicable fix ("this version or later")
  nginx-mainline: 1.31.9-r0
  nginx-stable: 1.30.7-r0
  nginx-iamguarded: 1.31.9-r0
  commercial-nginx-plus: 37.3.0.1-r0  # per F5's CVE records; not independently verified by Chainguard
  openresty: 1.31.8.1-r1             # version unchanged: only the -r1 revision has the fixes
  apache-apisix: 3.20.0-r1
  kong: 3.9.4-r5
  ingress-nginx-controller-1.15: 1.15.16-r0
  ingress-nginx-controller-fips-1.15: 1.15.16-r0
  angie: 1.12.4-r1                   # fork of NGINX 1.31.2; patched
  fabiocicerchia-nginx-lua: 1.31.8-r1  # NGINX 1.31.8 with Lua modules; patched
partial:                             # builds with only some of the fixes: still VULNERABLE, update again
  ingress-nginx-controller-1.15: {version: 1.15.15-r0, fixes: [CVE-2026-123633, CVE-2026-123007]}
  ingress-nginx-controller-fips-1.15: {version: 1.15.15-r0, fixes: [CVE-2026-123633, CVE-2026-123007]}
not_applicable:                      # module not built into the package, so the CVE can't apply
  apache-apisix: [CVE-2026-113425]
  kong: [CVE-2026-121810, CVE-2026-113425]
  ingress-nginx-controller-1.15: [CVE-2026-113425]
  ingress-nginx-controller-fips-1.15: [CVE-2026-113425]
end_of_life:                         # no fixed build will ship: move to a supported line
  ingress-nginx-controller-1.12: "upgrade to ingress-nginx-controller 1.15"
  ingress-nginx-controller-1.13: "upgrade to ingress-nginx-controller 1.15"
  ingress-nginx-controller-1.14: "upgrade to ingress-nginx-controller 1.15"
  ingress-nginx-controller-fips-1.12: "upgrade to ingress-nginx-controller-fips 1.15"
  ingress-nginx-controller-fips-1.13: "upgrade to ingress-nginx-controller-fips 1.15"
  ingress-nginx-controller-fips-1.14: "upgrade to ingress-nginx-controller-fips 1.15"
image_streams_not_rebuilt:           # images whose older version streams still carry an older NGINX
  harbor-portal: {streams: "2.12 and earlier", variants: [harbor-portal, harbor-portal-fips, harbor-portal-iamguarded, harbor-portal-iamguarded-fips], action: "move to 2.13 or later"}
public_repo_unfixed:                 # the public package repository (packages.wolfi.dev, apk.cgr.dev/chainguard) keeps these
  nginx-stable: 1.30.2-r0            # both moved to the Chainguard private package repository in June 2026;
  kong: 3.9.2-r1                     # the public builds won't be updated: install from the org's private repository
subpackages: >-
  A subpackage carries its origin's version. Map an SBOM or apk name to its origin: take the longest key in
  fixed_versions, partial or end_of_life that equals the name or is followed by "-" (nginx-mainline-mod-mail
  and nginx-mainline-full map to nginx-mainline; apache-apisix-iamguarded-compat maps to apache-apisix).
sbom_nginx_regex: '^(nginx-(mainline|stable)(-full|-privileged-netbindservice|-src|-mod-mail)?|nginx-iamguarded(-src)?|commercial-nginx-plus(-privileged-netbindservice)?|openresty|apache-apisix(-iamguarded-compat)?|kong|angie|fabiocicerchia-nginx-lua|ingress-nginx-controller(-fips)?-1[.][0-9]+)$'
                                     # exactly the Chainguard packages that carry NGINX code: a server binary or ngx_mail_module.so
builds:                              # what each package compiles in (http2 / http3 / mail); decides which CVEs step 3b checks
  nginx-mainline: {http2: yes, http3: no, mail: "module package nginx-mainline-mod-mail"}
  nginx-stable: {http2: yes, http3: no, mail: "module package nginx-stable-mod-mail"}
  nginx-mainline-full: {http2: yes, http3: yes, mail: yes}
  nginx-stable-full: {http2: yes, http3: yes, mail: yes}
  nginx-iamguarded: {http2: yes, http3: no, mail: "ngx_mail_module.so shipped, not loaded by default"}
  commercial-nginx-plus: {http2: yes, http3: yes, mail: yes}
  openresty: {http2: yes, http3: yes, mail: yes}
  apache-apisix: {http2: yes, http3: yes, mail: no}
  kong: {http2: yes, http3: no, mail: no}
  ingress-nginx-controller: {http2: yes, http3: yes, mail: no}   # 1.15; the 1.12.4-r0 build in the public repository has no HTTP/3
  angie: {http2: yes, http3: yes, mail: yes}
  fabiocicerchia-nginx-lua: {http2: yes, http3: yes, mail: yes}
defaults:                            # what the shipped configuration turns on
  http2_on_by_default:
    ingress-nginx-controller: 'use-http2: "true" in the controller ConfigMap (the default when unset), in every server block'
    kong: "proxy_listen 0.0.0.0:8443 http2 ssl; admin_listen 127.0.0.1:8444 http2 ssl"
    apache-apisix: "enable_http2: true and ssl.enable: true (the defaults): http2 on; in the main server, which listens on 9080 (cleartext) and 9443 (TLS)"
  http2_off_by_default: [nginx-mainline, nginx-stable, nginx-iamguarded, openresty, angie, fabiocicerchia-nginx-lua]
                                     # the shipped configuration listens on 80 or 8080 without http2
  quic_and_mail_by_default: none     # no shipped configuration of these packages has a quic listener or a mail {} block
upstream_fixed:                      # for an NGINX binary no package records: compare its nginx/X banner (step 3)
  "1.31": "1.31.9"
  "1.30": "1.30.7"
banners_on_fixed_builds:             # expected version strings; they don't show the fix
  ingress-nginx-controller: nginx/1.27.1
  kong: openresty/1.25.3.2
  openresty: openresty/1.31.8.1
  apache-apisix: openresty/1.31.8.1
  commercial-nginx-plus: "nginx/1.31.8 (nginx-plus-r37.3.0): F5's fourth version number is a packaging revision the banner omits"
  angie: "Angie/1.12.4 (nginx/1.31.2)"
  fabiocicerchia-nginx-lua: nginx/1.31.8
no_nginx:                            # carry no NGINX code, despite the name
  nginx-gateway-fabric: >-
    The Chainguard image is the control plane only. The NGINX data plane it deploys comes from the chart's
    nginx.image value, which defaults to the upstream project's image; F5 lists NGINX Gateway Fabric 2.9.0 as fixed.
  controllers_and_exporters: [nginx-kubernetes-ingress, commercial-nginx-ingress, kong-ingress-controller,
                              nginx-prometheus-exporter, nri-nginx]   # their images get NGINX, if any, from the packages above
scanner_feeds:                       # list the backported fixes; version bumps rely on the scanner's own NGINX data
  - https://packages.cgr.dev/chainguard/security.json
  - https://packages.wolfi.dev/os/security.json
signature_verify:                    # KB section on signature verification, with the org regexp anchored; also used to verify SBOMs in step 2a
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

1. Check the tools: `docker` (or `podman`), `cosign`, `jq`, `crane`, `chainctl`; `kubectl` if Kubernetes is in scope. Report what's missing; don't install anything without approval.
2. Ask the user, if not already known:
   - their Chainguard organization (`ORG`, as in `cgr.dev/$ORG/...`)
   - which repositories, directories and clusters (kube contexts) are in scope
   - any **mirror or cache registries** that hold copies of Chainguard images (e.g. `registry.corp/cg/...`)
3. Confirm auth without touching credentials. `chainctl auth status -o json | jq -e .valid` must print `true` before step 2: with an expired session, cosign and crane can hang on the credential helper with no error. If it isn't valid, ask the user to log in. Wrap registry calls in `timeout 120` (`gtimeout` on macOS with coreutils) where available. Also check `kubectl config current-context` if Kubernetes is in scope.
4. For an org registry, look up the org's two signing identities now (steps 2a and 5 use them). Check both as described in step 5 before using them:
   ```sh
   IMAGE_SYNCER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.CATALOG_SYNCER')
   CUSTOM_IMAGE_BUILDER=$(chainctl iam account-associations describe "$ORG" -o json | jq -r '.[].chainguard.service_bindings.APKO_BUILDER')
   ```
5. If a mirror or internal registry only serves plain HTTP (anything other than `localhost`), stop and ask the user how they normally reach it. Don't add insecure flags yourself (ground rule 4).

## Step 1: Inventory every place a Chainguard image, NGINX package or NGINX configuration is used (read-only)

Collect **image references** (`registry/repo:tag` or `@sha256:…`) with the file and line, or workload, where each is used.

**Primary: `chainctl images discover`** (newer chainctl; check with `chainctl images discover --help`). It reads Helm values as written, including a split `registry`/`repository`/`tag` and a global image registry, plus Compose, Terraform, Kubernetes manifests and Dockerfiles, and reports file and line:

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

# Builds that install NGINX themselves: Dockerfiles, apko configs and apko lockfiles. Match the package name
# alone, because `apk add` is often continued over several lines; read the surrounding lines.
NGX_PKG_RE='(^|[^A-Za-z0-9.-])(nginx-(mainline|stable|iamguarded)|commercial-nginx-plus|openresty|apache-apisix|kong|angie|fabiocicerchia-nginx-lua|ingress-nginx-controller)([^A-Za-z0-9.]|$)'
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE "$NGX_PKG_RE" {} +
grep -rnE "$NGX_PKG_RE" <paths> --include='*.yaml' --include='*.yml' --include='*.lock.json' --include='*.tf'
# ...and which repository they install from: the public one keeps unfixed nginx-stable and kong (public_repo_unfixed)
grep -rnE 'packages\.wolfi\.dev|apk\.cgr\.dev/chainguard([^-]|$)' <paths>

# Builds that copy NGINX out of another stage
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE 'COPY[[:space:]]+--from=.*(nginx|openresty)' {} +

# NGINX configuration kept in the repo, for step 3b
grep -rlE '^[[:space:]]*(listen|server_name|proxy_pass|http2|resolver|mail)[[:space:]]' <paths> --include='*.conf' --include='*.conf.template' --include='nginx.conf*'
grep -rnE 'use-http2|server-snippet|configuration-snippet|http-snippet|auth-url|mirror-target|KONG_(PROXY|ADMIN)_LISTEN|proxy_listen|admin_listen' <paths> --include='*.yaml' --include='*.yml' --include='*.conf'

# Running pods, including init and ephemeral containers (imageID = the digest the node pulled)
kubectl get pods -A -o json | jq -r '.items[] | .metadata as $m
  | ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) + (.status.ephemeralContainerStatuses // []))[]
  | [$m.namespace, $m.name, .image, .imageID] | @tsv'
# Workload specs, which catch Jobs and CronJobs with no live pod
kubectl get deploy,sts,ds,job,cronjob -A -o json | jq -r '.items[] | .kind as $k | .metadata as $m
  | (.spec.jobTemplate.spec.template.spec // .spec.template.spec)
  | ((.initContainers // []) + (.containers // []))[] | [$k, $m.namespace, $m.name, .image] | @tsv'
# ConfigMaps that hold NGINX configuration (ingress-nginx controller settings, mounted nginx.conf)
kubectl get configmap -A -o json | jq -r '.items[] | select(.data // {} | to_entries | any(.key == "use-http2" or (.value | test("listen[^;]*;|^[[:space:]]*http2[[:space:]]"; "m"))))
  | [.metadata.namespace, .metadata.name] | @tsv'
```

Helm values often split an image across `registry`, `repository`, `tag` and `digest` fields, sometimes with a global registry. When a grep match has no tag or digest, read the neighbouring lines (and any global registry) and join them into the full reference before step 2. `chainctl images discover` does this for you.

If the inventory includes **nginx-gateway-fabric**, also record the data-plane image it deploys (the chart's `nginx.image` value, or the image of the NGINX pods it creates). That image isn't Chainguard's: see `no_nginx` and step 4.

Deduplicate by image and digest. Don't filter by image name. Many images contain NGINX without being named for it (harbor-portal, zabbix web, swagger-ui, element-web and more), so check **every** Chainguard image.

## Step 2: Find NGINX in each image (read-only)

First decide, for each image, whether **Chainguard built it** or the **user built it**:
- Chainguard-built: it's in `cgr.dev/chainguard/...` or `cgr.dev/$ORG/...`, or it's a mirror copy whose digest matches the digest at `cgr.dev/$ORG` (compare `crane digest` on both).
- The user's own build: a different digest (derived images, `apk add` or apko builds, mirrors rebuilt rather than copied). Its `crane config` history shows the user's build steps.

Use **2a for Chainguard-built images** and **2b for the user's own builds**. That way a verification failure in 2a really does mean something is wrong.

Resolve tags to digests (`crane digest REF`). Then read the packages using the first method that works.

**2a. Signed SBOM attestation (Chainguard-built images).** Resolve the platform digest the workload runs, check whether an SBOM attestation exists, and read it **only through signature verification**: `cosign download attestation` doesn't check signatures, and a mirror or registry the user controls could serve anything. Set the verification flags with `set --` to the issuer and identity flags from `signature_verify` (`public` for `cgr.dev/chainguard/...`; `org_registry`, with the identities from step 0, for `cgr.dev/$ORG/...`). The block is plain POSIX `sh`:

```sh
PLAT=linux/amd64   # the platform the workload runs on (linux/arm64 too, if used)
NGX_RE='^(nginx-(mainline|stable)(-full|-privileged-netbindservice|-src|-mod-mail)?|nginx-iamguarded(-src)?|commercial-nginx-plus(-privileged-netbindservice)?|openresty|apache-apisix(-iamguarded-compat)?|kong|angie|fabiocicerchia-nginx-lua|ingress-nginx-controller(-fips)?-1[.][0-9]+)$'
case "$(crane manifest "$REF" | jq -r '.mediaType // empty')" in
  *image.index*|*manifest.list*) PDIG=$(crane digest --platform "$PLAT" "$REF") ;;
  *) PDIG=$(crane digest "$REF") ;;
esac
REPO=$(printf '%s' "$REF" | sed -E 's/@sha256:[a-f0-9]{64}$//; s#^(.*/[^/:]+):[^/]+$#\1#')   # REF without tag or digest
# Verification flags (public images shown). For cgr.dev/$ORG use:
#   set -- --certificate-oidc-issuer=https://issuer.enforce.dev \
#     --certificate-identity-regexp="^https://issuer\.enforce\.dev/(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})$"
set -- --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
if [ -z "$PDIG" ]; then
  echo "sbom: error (couldn't resolve the image digest; check access and the reference)"
else
  ERR=$(mktemp)
  # cosign versions differ when there's no attestation: v2 exits 0 with no output; v3 exits 1 with "no
  # attestations with predicate type ... found". Treat both as none, and anything else non-zero as an error.
  ATT=$(cosign download attestation --predicate-type=https://spdx.dev/Document "$REPO@$PDIG" 2>"$ERR"); RC=$?
  if [ "$RC" -eq 0 ] && [ -n "$ATT" ]; then
    if SBOM=$(cosign verify-attestation --type spdxjson "$@" "$REPO@$PDIG" 2>"$ERR"); then
      echo "sbom: found, verified"
      printf '%s\n' "$SBOM" | jq -r '.payload' | base64 -d | jq -r '"packages: \(.predicate.packages | length)"'
      printf '%s\n' "$SBOM" | jq -r '.payload' | base64 -d \
        | jq -r --arg ngx "$NGX_RE" '.predicate.packages[]
            | select(any(.externalRefs[]?; .referenceLocator | startswith("pkg:apk/")))   # skip upstream source entries
            | select(.name | test($ngx)) | "\(.name) \(.versionInfo)"' \
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

- `sbom: found, verified` plus package lines: rate them in step 3.
- `sbom: found, verified`, `packages: N` with N above 0, and no package lines: the image has no Chainguard package with NGINX code. Rate it `NOT AFFECTED` (the pattern was tested against every package in Chainguard's repositories). If `packages:` is 0 or missing, the SBOM wasn't read; use 2b.
- `sbom: found, NOT verified`: **stop** for this image (ground rule 8). It's a Chainguard-built image whose SBOM doesn't verify against Chainguard's identity. Don't mark it `UNKNOWN` and continue with 2b; report it and point the user to Support.
- `sbom: error`: cosign couldn't read the image, usually auth, network or a wrong reference. **Stop** for this image: ask the user to check access (for example `chainctl auth configure-docker`) and re-run 2a. Don't fall back to 2b, which would hit the same problem.
- `sbom: none`: there's no attestation to read. That's unusual for a Chainguard-built image (re-check that it really is one). Use 2b and say so in the report.

**2b. The image's filesystem (the user's own builds, and the fallback).** Use it for images the user built (derived images, `apk add` and apko builds, mirrors rebuilt rather than copied), even if they carry an SBOM of their own, which won't list an NGINX copied in from a build stage. Also use it when 2a prints `sbom: none`. This doesn't run the image, and works on single- and multi-arch references. It reports three things: whether there's an apk database, any NGINX packages it lists, and any NGINX executable or mail module on disk, with the version strings and HTTP/2, HTTP/3 and mail modules compiled into it. It also keeps the image's NGINX configuration files for step 3b:

```sh
NGX_RE='^(nginx-(mainline|stable)(-full|-privileged-netbindservice|-src|-mod-mail)?|nginx-iamguarded(-src)?|commercial-nginx-plus(-privileged-netbindservice)?|openresty|apache-apisix(-iamguarded-compat)?|kong|angie|fabiocicerchia-nginx-lua|ingress-nginx-controller(-fips)?-1[.][0-9]+)$'
echo "arch: $(crane config --platform "$PLAT" "$REF" | jq -r '.architecture')"   # must match the workload's platform
FS=$(mktemp)     # needs disk space roughly twice the size of the image: the export, then its unpacked files
CONF=$(mktemp -d)  # the image's NGINX configuration, kept for step 3b; remove it when done
if ! crane export --platform "$PLAT" "$REF" - > "$FS" || [ ! -s "$FS" ]; then
  echo "export: error"   # stop for this image: an empty export would look like "no NGINX"
else
  X=$(mktemp -d)  # the image's filesystem, unpacked; nothing in it is run
  if ! tar -xf "$FS" -C "$X" 2>/dev/null && [ -z "$(ls -A "$X")" ]; then
    echo "unpack: error"
  else
    chmod -R u+rwX "$X" 2>/dev/null
    DB=""
    for d in usr/lib/apk/db/installed lib/apk/db/installed; do [ -f "$X/$d" ] && DB="$d" && break; done
    if [ -n "$DB" ]; then
      echo "apk-db: $DB"
      awk -F: -v re="$NGX_RE" '/^P:/{p=substr($0,3)} /^V:/{if (p ~ re) print "package:", p, substr($0,3)}' "$X/$DB" | sort -u
    else
      echo "apk-db: none"
    fi
    # NGINX code on disk, whether or not a package owns it. Every NGINX build carries its module table
    # (ngx_core_module ...; the mail module's own table names ngx_mail_module). A server binary also has the
    # "nginx version: " string; a dynamic module doesn't. Module names are read as whole NUL-separated strings,
    # the way the table stores them: the same name inside another string doesn't mean the module is built in.
    # Scanners and CLIs (grype, syft, chainctl, ...) contain "nginx version: " as a detection pattern but no
    # module table, so they don't match.
    grep -rlaE 'ngx_core_module|ngx_mail_module' "$X" 2>/dev/null | while read -r b; do
      [ "$(head -c 4 "$b" | od -An -c | tr -d ' ')" = '177ELF' ] || continue   # ELF files only
      if LC_ALL=C grep -qaE '(nginx|Angie|tengine) version: ' "$b"; then
        echo "nginx-binary: /${b#"$X"/} $(LC_ALL=C grep -aoE '(nginx|openresty|Angie|freenginx|tengine)/[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?' "$b" | sort -u | tr '\n' ' ')modules: $(LC_ALL=C tr '\000' '\n' < "$b" | LC_ALL=C grep -axE 'ngx_(http_v2|http_v3|mail)_module' | sort -u | tr '\n' ' ')"
      else
        case "$b" in *ngx_mail_module*.so) echo "mail-module: /${b#"$X"/}" ;; esac
      fi
    done
    # Keep the NGINX configuration for step 3b
    for d in etc/nginx usr/local/openresty/nginx/conf opt/iamguarded/nginx/conf etc/kong usr/local/share/lua/5.1/kong/templates/kong_defaults.lua; do
      [ -e "$X/$d" ] && mkdir -p "$CONF/$(dirname "$d")" && cp -R "$X/$d" "$CONF/$d"
    done
    echo "config: $CONF"
  fi
  chmod -R u+w "$X" 2>/dev/null; rm -rf "$X"
fi
rm -f "$FS"
```

This exports and unpacks the image's whole filesystem, so it's slower and needs disk space for large images. If `arch` isn't the platform the workload runs on, the image doesn't have that platform and crane exported a different one: report it and check the reference the workload actually pulls.

What the lines look like (from Chainguard images):

```
package: nginx-mainline 1.31.9-r0
nginx-binary: /usr/bin/nginx nginx/1.31.9 modules: ngx_http_v2_module
nginx-binary: /usr/bin/nginx openresty/1.31.8.1 modules: ngx_http_v2_module ngx_http_v3_module ngx_mail_module
nginx-binary: /usr/bin/nginx nginx/1.27.1 modules: ngx_http_v2_module ngx_http_v3_module            # ingress-nginx-controller
mail-module: /usr/lib/nginx/modules/ngx_mail_module.so
```

Interpreting the result:
- **`export: error` or `unpack: error`:** stop for this image and check access, as for `sbom: error`.
- **`package`, `nginx-binary` or `mail-module` lines:** rate each one in step 3. NGINX installed from a package shows up as both a `package` line and an `nginx-binary` line; that's one finding, not two.
- **None of these:** `NOT AFFECTED`.
- Distroless Chainguard bases such as `glibc-dynamic` and `static` still have an apk database, so an empty package list alone proves nothing; the `nginx-binary` check is what catches an NGINX copied in from a build stage.
- For mirrored images, read from the mirror. If the mirror has no attestation, 2b on the mirror is the authoritative check of what you actually run.

## Step 3: Compare versions exactly (read-only)

**Never compare version strings as text** (`3.9.4-r5` vs `3.9.4-r10`, `1.31.8.1-r0` vs `1.31.8.1-r1`). Use apk's own comparator:

```sh
docker run --rm cgr.dev/chainguard/wolfi-base apk version -t "<installed>" "<fixed>"   # prints <, = or >
```

Rate each finding from step 2 with the first rule that applies:

1. **A package line** (from 2a or 2b). Map the name to its origin as `subpackages` describes, then:
   - origin in `end_of_life`: `END OF LIFE`. No fixed build will ship; step 4 proposes the upgrade named there.
   - origin in `fixed_versions`: `PATCHED` at or above the fixed version. Below it: `VULNERABLE`. If the origin is in `partial` and the build is at or above the partial version, it's still `VULNERABLE`; note "has only the HTTP/2 fixes" in the Action column.
   - matches `sbom_nginx_regex` but appears in none of these: `UNKNOWN`, with "not in this skill's data" in the Action column. Check the KB, or ask Support.
2. **An `nginx-binary` line that no package line explains** (an NGINX copied in, built from source or unpacked from a tarball):
   - banner `nginx/X` only: take the line from the first two parts (`nginx/1.31.8` is line 1.31) and compare with `upstream_fixed`. At or above it: `PATCHED`, noted "by binary version". Below it: `VULNERABLE`. A line not in `upstream_fixed` (1.29 and older, or 1.32 and later): `UNKNOWN`; check NGINX's security advisories for that release (`disclosure`).
   - banner `openresty/`, `Angie/`, `tengine/`, `freenginx/`, or an NGINX Plus build: `UNKNOWN`. Backported fixes don't change these version strings, so only the package that built the binary can show the fix. Find where it came from (read the Dockerfile) and check that source with steps 2–3.
3. **A `mail-module` line that no package line explains:** `UNKNOWN`. Find the package or build stage it came from.

Then, one status per image, the first that applies:

| Status | When |
|---|---|
| `UNKNOWN` | 2a or 2b couldn't be read, or any finding rated `UNKNOWN` |
| `END OF LIFE` | any finding rated `END OF LIFE` |
| `VULNERABLE` | any finding rated `VULNERABLE` |
| `PATCHED` | every finding rated `PATCHED` |
| `NOT AFFECTED` | no NGINX package, no `nginx-binary` and no `mail-module` line |

After step 4, a `VULNERABLE` Chainguard-built image whose fix isn't in the user's registry yet becomes `WAITING ON CHAINGUARD`.

**Dockerfiles with no built image to inspect:** rate them from their pins, repositories and base images. An `apk add` pin below the fixed version is `VULNERABLE`; so is an unpinned `apk add nginx-stable` or `kong` from the public repository (`public_repo_unfixed`). Otherwise check each `FROM` image with steps 2–3, including any build stage NGINX is copied from, and check the image the Dockerfile produces once it's built.

**apko configs and lockfiles:** the lockfile decides the version, but **only if the build passes `apko build --lockfile …`**; apko doesn't pick it up on its own, so check the Makefile or CI. Read the locked version per architecture:

```sh
jq -r --arg ngx "$NGX_RE" '.contents.packages[] | select(.name | test($ngx)) | "\(.name) \(.version) \(.architecture)"' apko.lock.json
```

Any entry below the fixed version is `VULNERABLE` (note "by lock"). Without a lockfile in use, an exact pin (`nginx-mainline=1.31.8-r0`) below the fixed version is `VULNERABLE` (note "by pin"); a fuzzy pin (`~`) or an unpinned package resolves at build time, so check the built image.

## Step 3b: Check exposure in the NGINX configuration (read-only)

Do this for every image that isn't `PATCHED` or `NOT AFFECTED`. It doesn't change the status; it tells the user how urgent each image is and which stopgaps in step 6 apply. Work only from configuration you can read without changing anything:

- configuration in the repositories (step 1), including Helm values, ConfigMaps, Kong environment variables (`KONG_PROXY_LISTEN`, `KONG_ADMIN_LISTEN`) and ingress-nginx annotations and snippets;
- the image's own configuration, kept by step 2b (`config:`);
- the live configuration of a running container, with `kubectl exec <pod> -c <container> -- nginx -T`. This is read-only, but it runs a command inside the workload: **ask the user first** (ground rule 2), and don't use it on images without an `nginx` command on the path.

For each CVE, check only what the package's `builds` row says is compiled in (a CVE in `not_applicable` for the package is `not applicable`), and report `exposed`, `not exposed by this configuration`, or `unknown (configuration not found)`:

| CVE | Exposed when the configuration has | How to check |
|---|---|---|
| CVE-2026-123007 | HTTP/2 on any reachable listener | `listen ... http2` or `http2 on;` anywhere (`grep -rnE '^[^#]*listen[^;#]*[[:space:]]http2|^[[:space:]]*http2[[:space:]]+on' <conf>`; the `^[^#]*` skips commented-out lines). One `listen ... http2` turns HTTP/2 on for every server on that address and port, even one with `http2 off;`. ingress-nginx-controller: on unless the controller ConfigMap sets `use-http2: "false"`. Kong: on unless `proxy_listen`/`admin_listen` drop `http2` from 8443 and 8444. Apache APISIX: on unless its config.yaml sets `apisix.enable_http2: false` (see `defaults`). |
| CVE-2026-123633 | HTTP/2 on, **and** requests proxied to an upstream | The HTTP/2 check above, plus `proxy_pass`, `grpc_pass`, `fastcgi_pass`, `uwsgi_pass` or `scgi_pass` in a server that HTTP/2 reaches. ingress-nginx-controller, Kong and Apache APISIX always proxy. |
| CVE-2026-123634 | a `resolver`, a proxied target containing a variable that can evaluate to a hostname, **and** a second lookup in the same request | `resolver` plus `*_pass` with a `$variable` in the target, plus `ssi on`, `mirror`, `add_before_body`/`add_after_body`, or njs `r.subrequest()`. A variable is safe only if every value it can take is an `upstream {}` name or an IP address. ingress-nginx-controller: the default configuration does no request-time lookups, but snippets and the `auth-url` and `mirror-target` annotations can add them. |
| CVE-2026-121810 | an HTTP/3 build **and** a `quic` listener | `grep -rnE '^[^#]*listen[^;#]*[[:space:]]quic' <conf>`. Also confirm on the host: `ss -lunp` shows a UDP listener owned by NGINX. None of the shipped configurations in `defaults` has one; Apache APISIX adds one only with `enable_http3: true` on an `ssl.listen` entry. |
| CVE-2026-113425 | the mail module **and** a `mail {}` block with a listening server | `mail {` in the configuration, and the module compiled in (`builds`) or loaded with `load_module ... ngx_mail_module.so`. |

A CDN, WAF or layer-7 load balancer in front only reduces the risk, and only if NGINX can't be reached any other way. A layer-4 or TLS-passthrough load balancer gives no protection. Report exposure next to the status (see Report format), never instead of it.

Show the user the inventory table now (see Report format) before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

For **images Chainguard builds** (catalog, Custom Assembly and custom images), first check whether a patched build exists **in the user's registry**: resolve the tag's current digest and repeat steps 2–3 on it. If it's still vulnerable, go to step 6 for that image. To list newer builds of a tag in an org registry: `chainctl images history IMAGE:TAG --parent $ORG`. For **images the user builds**, the fix is a rebuild (rows below), not Support.

To tell a mirror copy from the user's own build: a mirror copy has the same digest as the image in `cgr.dev/$ORG` (compare `crane digest` on both); the user's own build has a different digest, and its `crane config` history shows their build steps.

| How it's referenced | Proposed change |
|---|---|
| By tag (`:latest`), and the tag now points to a patched digest | Propose pinning the reference to the digest you verified in steps 2–3 and 5 (`IMAGE:TAG@sha256:…`), then roll out (step 7). A restart alone can reuse a cached image (`imagePullPolicy: IfNotPresent`), and the tag can move after you verified it. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror | Propose copying the **verified digest**, not the tag (which can move): `cosign copy cgr.dev/$ORG/IMAGE@sha256:<verified> <mirror>/IMAGE:TAG`. This copies signatures and attestations too. Then compare digests on both sides. |
| Via a pull-through cache (Artifactory remote repo, Harbor proxy cache) | These can't receive a push. Propose refreshing or expiring the cached tag, or referencing the verified digest, which the cache will fetch. |
| Derived image (`FROM cgr.dev/...`) | If the `FROM` line is pinned by digest, first propose bumping it to a verified, patched digest (show the diff): rebuilding a pinned base rebuilds the same vulnerable image. Then rebuild with `--pull --no-cache`, push, and update references to the new image. Verify the rebuilt image with steps 2–3: it has no Chainguard attestation, so step 2b applies. |
| NGINX copied from a build stage | The copy keeps the version of the stage it came from; updating the final stage's base image doesn't change it. Propose bumping the **build stage** (its `FROM`, or its `apk add` pins) to a patched version, then rebuild with `--pull --no-cache` and verify with step 2b. |
| Dockerfile or apko config with `apk add` of an NGINX package | Raise or remove old pins and fail closed, for example `apk add --no-cache 'nginx-mainline>=1.31.9-r0'`. Upgrade every NGINX subpackage it installs too (`-mod-*`, `-config`). Rebuild with `--pull --no-cache`, then verify the result with steps 2b–3. For apko, regenerate the lockfile with `apko lock`; that moves **every** package, so show the whole lockfile diff for approval. If a policy blocks the new versions, tell the user to contact their org admin or Support; don't change policy yourself. |
| `nginx-stable` or `kong` installed from the public repository | The public builds (`public_repo_unfixed`) won't be updated. Propose installing from the org's private repository instead (served from `apk.cgr.dev/<organization>`; the exact address is in the Chainguard Console's Settings tab), or using a current Chainguard image. If the user mirrors the public repository, the mirrored versions must be replaced too. |
| Custom Assembly image | These rebuild automatically unless the configuration pins NGINX package versions. If your chainctl has it, read the pins with `chainctl images overlays list --parent "$ORG" -o json` (packages under `.overlays[].config.contents.packages`, repos under `.bindings[]`; check the output's shape before relying on it). Otherwise ask the user to check the configuration in the Chainguard Console. Propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| ingress-nginx-controller 1.15 at 1.15.15-r0 | That build has only the HTTP/2 fixes (`partial`). Update again to 1.15.16-r0 or later, as for any vulnerable reference. |
| ingress-nginx-controller 1.12, 1.13 or 1.14 (`end_of_life`) | Past their end-of-life grace period and no longer rebuilt. Propose upgrading to 1.15. That's a version upgrade of the controller, so check the upstream release notes and the user's ingress resources with them; don't change anything automatically. |
| harbor-portal on a 2.12 or earlier stream (`image_streams_not_rebuilt`) | Not rebuilt; still carries an older NGINX. Propose moving to 2.13 or later, as part of the user's Harbor upgrade. |
| nginx-gateway-fabric data plane | Chainguard's image is the control plane only (`no_nginx`). Propose upgrading NGINX Gateway Fabric to 2.9.0, which F5 lists as fixed, so the control plane and the data plane move together, then confirm the data-plane pods run the new image. The data-plane image comes from the upstream project; its version isn't verified by Chainguard. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block, substituting `IMAGE@DIGEST`. Use `public` for `cgr.dev/chainguard/...` and `org_registry` for `cgr.dev/$ORG/...`. Images the user builds themselves aren't signed by Chainguard; verify them with the user's own signing policy, if any. For a mirror, verify the `cgr.dev` digest you copied from, or the mirror copy if it was made with `cosign copy`.

For the org registry, use the org's two signing identities from step 0.

**Check both values before running cosign.** Each must be a non-empty identity of the form `<hex>/<hex>`, not empty and not `null`. cosign matches `--certificate-identity-regexp` anywhere in the certificate subject, so an empty alternative in `(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})` would accept a signature from *any* `issuer.enforce.dev` identity. If one value is missing, drop it from the group (for example `(${IMAGE_SYNCER})`). If both are missing, stop: report it, and point the user to Support.

If verification fails for an image, **stop**: don't deploy that image; report it and point the user to Support. Never retry with a looser identity or issuer.

## Step 6: If the fix isn't in the user's registry yet, or the user can't update yet

Patched images reach customer registries automatically after Chainguard publishes them; this can take additional time.

- Report the image, tag and digest as `WAITING ON CHAINGUARD`, and help the user open a Support request at https://support.chainguard.dev, including the image, tag, digest and the NGINX package version from step 2.
- Don't switch the user to public images or another registry as a workaround; that's a Support decision.

If the user can't update yet, offer the stopgaps that match the exposure from step 3b. **None of them replaces the update**: say so, and say what each leaves open. F5 lists no mitigation for CVE-2026-123633, CVE-2026-123007 or CVE-2026-121810, and ASLR isn't a mitigation (bypasses have been shown). Each stopgap is a configuration change: show the diff and wait for approval (ground rule 2).

| CVE | Stopgap | What it leaves open |
|---|---|---|
| CVE-2026-123633, CVE-2026-123007 | Turn HTTP/2 fully off: remove `http2` from every `listen` directive, remove every `http2 on;` (`http2 off;` alone isn't enough), and for ingress-nginx-controller set `use-http2: "false"` in the controller ConfigMap. Check with `nginx -T \| grep -n http2`. **Restart** NGINX; don't reload, because open HTTP/2 connections survive a reload. Verify against NGINX directly, not through a CDN or proxy: `openssl s_client -alpn h2 -connect HOST:PORT` must not negotiate `h2`. | Native gRPC breaks, and gRPC front ends can't use this stopgap. Raising `worker_connections` doesn't help. On a TLS port, one server with HTTP/2 on keeps it reachable on that port; on a cleartext port, the default server decides for every server name. No HTTP/2 tuning directive is a documented mitigation. |
| CVE-2026-123634 | Point each affected `*_pass` at a fixed `upstream {}` group or an IP address, in every location a subrequest can reach. | Turning off `mirror` alone isn't enough, because SSI reaches the same code. A trusted internal resolver doesn't help when the client chooses the name (for example with `$host`). Per-request dynamic routing breaks. |
| CVE-2026-121810 | Remove `quic` from every `listen` directive on the address and port, in every server block that shares it. Restart NGINX, then confirm with `ss -lunp` that no NGINX UDP listener remains. | `http3 off;` alone isn't enough: the UDP socket stays bound and other server blocks keep serving HTTP/3. A firewall rule must cover every port with a QUIC listener, not only 443. |
| CVE-2026-113425 | If the mail proxy isn't used, remove the `mail {}` block and its `load_module` line. Otherwise bind it to loopback, or allow-list source addresses at the firewall, NetworkPolicy or load balancer. | The flaw stays reachable from every allowed address. Behind a load balancer, filter at the load balancer. Cover every mail port: 25, 110, 143, 465, 587, 993, 995 and any custom one. |

A clean error log doesn't prove there was no attempt.

## Step 7: Apply approved changes and roll out

- Make only the approved edits. Commit on a branch and open a PR if the repo uses one.
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`), with the references pinned to verified digests. Don't rely on `kubectl rollout restart` for tag references: nodes that cached the tag keep running the old image. Running containers don't update themselves, and `nginx -s reload` doesn't replace the running binary.
- Sync mirrors before redeploying anything that pulls from them.

## Step 8: Re-verify and report

1. Re-run the step 1 `kubectl` query and confirm every affected workload now runs a `PATCHED` digest (repeat steps 2–3 on the running `imageID`s, not just the manifests).
2. Scanners: Chainguard's feeds (`scanner_feeds`) list the backported fixes (openresty, apache-apisix, kong, ingress-nginx-controller 1.15). Packages fixed by moving to NGINX 1.31.9 or 1.30.7 have no feed entry; scanners rate those from their own NGINX vulnerability data, which may not list these CVEs yet. A clean scan therefore doesn't confirm a fix: steps 2–3 do. If a scanner flags one of these CVEs on an image step 3 rated `PATCHED`, refresh its database (for grype: `grype db update`), confirm it reads a feed in `scanner_feeds`, and contact Support with the image digest and scanner version if it persists.
3. Produce the final report.

### Report format

```
Chainguard NGINX2Root (CVE-2026-123633, CVE-2026-123007, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425) — remediation report (<date, UTC>)

| Where used (file:line / ns/workload) | Image reference | Digest | NGINX found (package / binary) | Status | Exposure (step 3b) | Action taken / proposed |
|---|---|---|---|---|---|---|
| k8s ingress/controller-7f9 | cgr.dev/acme/ingress-nginx-controller:1.15 | sha256:… | ingress-nginx-controller-1.15 1.15.15-r0 | VULNERABLE → PATCHED | HTTP/2 on (default use-http2) | has only the HTTP/2 fixes; pinned verified digest with 1.15.16-r0 (approved 14:02) |
| web/Dockerfile:3 | registry.corp/web:2.1 | sha256:… | nginx-stable 1.30.2-r0 | VULNERABLE | HTTP/2 off; no resolver, quic or mail | installed from the public repository; switch to the org's private repository (proposed) |
| k8s gw/kong-0 | cgr.dev/acme/kong:3.9 | sha256:… | kong 3.9.4-r5 | PATCHED | HTTP/2 on 8443, 8444 | none |

Summary: N references checked · patched · not affected · vulnerable · end of life · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses (from step 3, plus step 4's `WAITING ON CHAINGUARD`): `PATCHED`, `NOT AFFECTED`, `VULNERABLE`, `END OF LIFE`, `UNKNOWN`, `WAITING ON CHAINGUARD`. Put the reason in the Action column (for example "pin in web/Dockerfile:4", "by binary version" or "copied from build stage `build`"), not in the status.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| `nginx -v` or the `Server:` header still shows an old version on a fixed image | Expected for backported fixes (`banners_on_fixed_builds`). Decide from the package version and revision (steps 2–3) |
| OpenResty is still 1.31.8.1 | Expected: the fix is in `1.31.8.1-r1`. Compare the full version with its revision |
| NGINX Plus reports `r37.3.0`, not `37.3.0.1` | Expected: F5's fourth version number is a packaging revision the banner omits. The package version `37.3.0.1-r0` is what counts |
| A scanner shows none of these CVEs, on fixed and unfixed images alike | Scanner data may not list them yet; rely on steps 2–3 |
| Scanner still reports the CVEs on a patched image | Stale scanner DB or wrong feed → refresh, confirm `scanner_feeds`; re-check the version with steps 2–3 |
| ingress-nginx-controller updated but still reported vulnerable | 1.15.15-r0 has only the HTTP/2 fixes → update to 1.15.16-r0 |
| `apk add nginx-stable` or `kong` installs an old version | Installing from the public repository (`public_repo_unfixed`) → install from the org's private repository |
| HTTP/2 turned off, but `openssl s_client -alpn h2` still negotiates `h2` | Another `listen ... http2` on the same address and port, a remaining `http2 on;`, or NGINX was reloaded, not restarted (step 6) |
| nginx-gateway-fabric updated, data plane still old | The data plane comes from the upstream image in the chart's `nginx.image` value (step 4) |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, a cached tag (`imagePullPolicy: IfNotPresent`), or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned NGINX package version in its configuration (step 4) |
| Own build still installs an old NGINX | Cached layer, an old `apk add` pin, or the public repository → `--pull --no-cache`, raise the pin, switch the repository |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the NGINX package version from step 2, and this report. Status updates: https://status.chainguard.dev.
