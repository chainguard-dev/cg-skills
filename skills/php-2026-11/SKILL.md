---
name: php-2026-11
description: >-
  Find, verify and remediate Chainguard images and packages affected by the
  PHP security release of 2026-11-19: 17 vulnerabilities (7 critical) fixed in
  PHP 8.2.36, 8.3.37, 8.4.28 and 8.5.13. Covers the php, php-fips and
  frankenphp images, images that bundle PHP (WordPress, Drupal, Nextcloud,
  phpMyAdmin and others), images you build yourself, and every PHP subpackage
  and extension in them. Inventories image references in repos and running
  Kubernetes workloads, reads each image's SBOM and filesystem for PHP,
  reports which CVEs apply to the SAPIs and extensions installed, proposes and
  (with approval) applies fixes, then re-verifies. Use when the user mentions
  the November 2026 PHP security release, any of its CVEs, Chainguard's PHP
  advisory, or asks "are we patched?".
---

# Remediate the 2026-11-19 PHP security release (17 CVEs) in Chainguard images

Published by Chainguard for its customers. This skill implements the steps in Chainguard's KB article *"[ACTION REQUIRED] PHP security updates: update Chainguard images with PHP"* so an agent can carry them out in your environment. The human-readable KB remains the authority: if anything here disagrees with it, follow the KB and tell the user.

Three facts shape everything below:

- **Check every PHP subpackage, not only the main package.** PHP's extensions and SAPIs ship as separate packages (`php-8.4-soap`, `php-8.4-fpm`, `php-8.4-pdo`), each with the same version as `php-8.4`. An image can carry a fixed `php-8.4` next to an extension from the previous release, and that image is still vulnerable. Step 2 reads them all.
- **The fix is the version.** Chainguard ships these fixes as PHP's own releases, not as backported patches, so a PHP version at or above the fixed release is fixed. One exception: FrankenPHP's startup log (the `php_version` field of `FrankenPHP started`) reports the PHP version FrankenPHP was compiled against (8.5.12 on a fixed 8.5 image), not the PHP library it runs; the `X-Powered-By` header and `php -v` show the running version. Decide FrankenPHP images from the `php-8.N-frankenphp` package.
- **Which CVEs apply depends on what's installed; the fix doesn't.** The FPM, CGI, SOAP, DOM and Phar CVEs need that SAPI or extension; the engine, session, date and URL CVEs apply wherever PHP runs. Step 3b reports which ones apply so the user can prioritise, but an image on a vulnerable build is still `VULNERABLE`.

## Ground rules for the agent (read first, follow always)

1. **Discovery and verification are read-only.** Run them freely.
2. **Every change needs the user's explicit approval first**: editing files, pushing or copying images, building, deploying, restarting workloads, changing PHP configuration or policies. Show the exact diff or command, say what it affects, and wait for a yes. Approval for one change does not carry over to the next.
3. **Prefer the user's own change process.** If manifests live in Git (GitOps, Helm, Terraform), propose a branch or PR instead of changing a cluster directly. Ask before touching production.
4. **Never weaken security to make progress.** No skipping signature verification, no `--insecure` or `--allow-insecure-registry`, no disabling admission policies, no pinning *older* versions.
5. **Don't handle credentials.** If a registry, cluster or `chainctl` isn't authenticated, ask the user to log in themselves. Never print tokens or secrets.
6. **Report uncertainty instead of guessing.** If an image's SBOM or filesystem can't be read, mark it `UNKNOWN`, never "patched".
7. **Never try to trigger the bugs.** Don't send crafted requests or run exploit code against any image or service to "test" it. Verification is by version; applicability is by reading packages and configuration.
8. **Stop and escalate** if a patched version isn't available in the user's registry (step 6), or a signature fails to verify.

## Incident data (single source of truth: update this block for later rounds)

```yaml
released: 2026-11-19                 # PHP 8.2.36, 8.3.37, 8.4.28, 8.5.13 (and 8.6.0, which also has the fixes)
disclosure: https://github.com/php/php-src/security/advisories
cves:                                # component (PHP's own advisory), severity, branches affected (8.1 is end of life: see end_of_life)
  CVE-2026-129496: {ghsa: GHSA-gr4f-wgx5-jpfv, severity: critical, component: ext-date, branches: [8.2, 8.3, 8.4, 8.5], summary: "timezone cache use-after-free"}
  CVE-2026-126714: {ghsa: GHSA-fm2m-fjf5-v3cp, severity: critical, component: ext-session, branches: [8.2, 8.3, 8.4, 8.5], summary: "partially overwritten session files"}
  CVE-2026-115560: {ghsa: GHSA-658j-r8rw-q6mx, severity: critical, component: ext-session, branches: [8.2, 8.3, 8.4, 8.5], summary: "session serializer mismatch"}
  CVE-2026-129289: {ghsa: GHSA-qc49-hpvq-g2w6, severity: critical, component: sapi-fpm, branches: [8.2, 8.3, 8.4, 8.5], summary: "PHP-FPM request smuggling through an unread request body"}
  CVE-2026-129481: {ghsa: GHSA-g3vh-838c-65v7, severity: critical, component: ext-session, branches: [8.3, 8.4, 8.5], summary: "use-after-free after interrupted session shutdown"}
  CVE-2026-129474: {ghsa: GHSA-8mjj-2r7p-4hg2, severity: critical, component: engine, branches: [8.5], summary: "use-after-free in magic method backtraces"}
  CVE-2026-129182: {ghsa: GHSA-2fjv-p558-g82m, severity: critical, component: engine, branches: [8.5], summary: "use-after-free via last_fatal_error_backtrace after shutdown"}
  CVE-2026-128090: {ghsa: GHSA-68fq-fh7h-f8gr, severity: high, component: ext-phar, branches: [8.2, 8.3, 8.4, 8.5], summary: "Phar OpenSSL signature bypass via algorithm downgrade"}
  CVE-2026-128064: {ghsa: GHSA-f6gg-rchx-xw8j, severity: high, component: ext-standard, branches: [8.2, 8.3, 8.4, 8.5], summary: "mixed-case HTTPS and FTPS URLs sent in plaintext"}
  CVE-2026-127960: {ghsa: GHSA-mmf9-xm3v-hg2x, severity: high, component: ext-standard, branches: [8.2, 8.3, 8.4, 8.5], summary: "denial of service through folded HTTP response headers"}
  CVE-2026-129291: {ghsa: GHSA-jm4m-qfqx-967m, severity: high, component: sapi-fpm, branches: [8.2, 8.3, 8.4, 8.5], summary: "PHP-FPM epoll use-after-free, local privilege escalation"}
  CVE-2026-129506: {ghsa: GHSA-4646-p932-gw34, severity: medium, component: ext-soap, branches: [8.2, 8.3, 8.4, 8.5], summary: "SOAP use-after-free on DTD entity references"}
  CVE-2026-15353:  {ghsa: GHSA-q23r-hr55-xmpg, severity: medium, component: ext-soap, branches: [8.2, 8.3, 8.4, 8.5], summary: "SOAP information disclosure through malformed array dimensions"}
  CVE-2026-129501: {ghsa: GHSA-x8r7-mg3g-74hg, severity: medium, component: ext-dom, branches: [8.4, 8.5], summary: "double free during DOM XML serialization"}
  CVE-2026-129538: {ghsa: GHSA-5j3f-64r7-f564, severity: medium, component: sapi-cgi, branches: [8.2, 8.3, 8.4, 8.5], summary: "PHP-CGI out-of-bounds read and write in PATH_INFO correction"}
  CVE-2026-129292: {ghsa: GHSA-3mg3-cr28-46gc, severity: medium, component: sapi-fpm, branches: [8.2, 8.3, 8.4, 8.5], summary: "PHP-FPM status page XSS"}
  CVE-2026-129438: {ghsa: GHSA-mg3p-mxj9-g2mm, severity: medium, component: ext-uri, branches: [8.5], summary: "incorrect RFC 3986 URI serialization for oversized input"}
advisories:                          # CVE -> CGA ID shared by every package's record in Chainguard's advisory data
  CVE-2026-129496: CGA-9g75-wxhx-6m5h
  CVE-2026-126714: CGA-25w8-789c-mwqg
  CVE-2026-115560: CGA-jr5r-fqcg-4xx9
  CVE-2026-129289: CGA-jjjj-6593-3496
  CVE-2026-129481: CGA-rjw5-v6r4-cf7p
  CVE-2026-129474: CGA-mx7j-2rfc-gq6r
  CVE-2026-129182: CGA-j47p-hp3h-7mp4
  CVE-2026-128090: CGA-v377-99jm-3fp2
  CVE-2026-128064: CGA-3g7f-m26h-2jc4
  CVE-2026-127960: CGA-r7xc-qh82-qw3c
  CVE-2026-129291: CGA-x2px-7rhh-w8qq
  CVE-2026-129538: CGA-25xm-fw5g-gxm6
  CVE-2026-129506: CGA-qg23-h6hw-3g34
  CVE-2026-15353:  CGA-7qm7-52gf-xgpw
  CVE-2026-129501: CGA-xfj8-xwg9-g339
  CVE-2026-129292: CGA-8xpj-95g8-f874
  CVE-2026-129438: CGA-93vp-59h2-pgm4
fixed_versions:                      # apk origin -> first fixed build ("this version or later"); every subpackage of the origin carries the same version
  php-8.2: 8.2.36-r0
  php-8.3: 8.3.37-r0
  php-8.4: 8.4.28-r0
  php-8.5: 8.5.13-r0
  php-8.6: 8.6.0-r0
  php-8.2-frankenphp: 8.2.36-r0
  php-8.3-frankenphp: 8.3.37-r0
  php-8.4-frankenphp: 8.4.28-r0
  php-8.5-frankenphp: 8.5.13-r0
  php-8.6-frankenphp: 8.6.0-r0
upstream_fixed:                      # for a PHP binary no package records: compare the version it reports (step 3)
  "8.2": "8.2.36"
  "8.3": "8.3.37"
  "8.4": "8.4.28"
  "8.5": "8.5.13"
  "8.6": "8.6.0"
end_of_life:                         # not part of this update: move to a supported line
  php-8.1: "This release has no fixed php-8.1 build; PHP 8.1 is end of life upstream (since 2025-12-31). At least CVE-2026-129291 and CVE-2026-127960 reach 8.1. Upgrade to 8.2 or later"
sbom_php_rule: >-
  A package carries PHP code if its name matches sbom_php_regex, does not match sbom_php_skip_regex, and its
  version starts with the branch in its name followed by "." (php-8.5-soap 8.5.13-r1 counts; php-8.5-xdebug
  3.5.3-r3 is a PECL extension with its own version and doesn't). Map it to its origin: php-8.N-frankenphp if the
  name starts with that, otherwise php-8.N.
sbom_php_regex: '^php-8[.][0-9]+(-frankenphp)?(-[a-z0-9_]+)?$'
sbom_php_skip_regex: '(-config|-doc|-pear|-src|-frankenphp-dev)$'   # configuration, docs and source only: no PHP code
where_the_code_is:                   # which installed package carries each component; decides which CVEs apply (step 3b)
  built_in: [engine, ext-date, ext-session, ext-standard, ext-uri]   # in every PHP binary: php, php-fpm, php-cgi, phpdbg, libphp.so
  sapi-fpm: "php-8.N-fpm (/usr/bin/php-fpm); not built into FrankenPHP"
  sapi-cgi: "php-8.N-cgi (/usr/bin/php-cgi); not built into FrankenPHP"
  ext-soap: "php-8.N-soap; not built into FrankenPHP"
  ext-dom: "php-8.N-dom; built into php-8.N-frankenphp"
  ext-phar: "php-8.N-phar; built into php-8.N-frankenphp"
frankenphp:                          # the frankenphp-8.N packages (FrankenPHP 1.13.5) load libphp.so from php-8.N-frankenphp
  rate_by: php-8.N-frankenphp
  version_strings_on_fixed_builds:   # in /usr/bin/frankenphp, from the PHP headers it was built against; step 2b prints them as "built against"
    "8.2": "X-Powered-By: PHP/8.2.35"
    "8.3": "X-Powered-By: PHP/8.3.36"
    "8.4": "X-Powered-By: PHP/8.4.27"
    "8.5": "X-Powered-By: PHP/8.5.12"
  startup_log: 'the php_version field of the "FrankenPHP started" log line shows this compile-time version'
  runtime: 'the X-Powered-By header and php -v show the running libphp.so version (PHP/8.5.13 on the fixed 8.5 image)'
defaults:
  session.upload_progress.enabled: >-
    Compiled-in default On before the fixed releases, Off in them (php-src ext/session/session.c). Chainguard's
    PHP packages ship no php.ini, so the compiled-in default applies unless an image or the user adds one.
  catch_workers_output: "yes, set by php-8.N-fpm-config in /etc/php/php-fpm.d/zz-apko.conf"
php_dependents:                      # Chainguard packages that depend on PHP (a hint only: always decide from the SBOM)
  [adminer, composer, drupal, linuxserver-heimdal (+fips), matomo (+fips), moodle, nextcloud-server, phpmyadmin (+fips),
   privatebin, renovate, roundcube, shlinkio-shlink, wordpress, zabbix (+fips)]
scanner_feeds:
  - https://packages.cgr.dev/chainguard/security.json
  - https://packages.wolfi.dev/os/security.json
signature_verify:                    # KB step 2 and its linked article on verifying signatures, with the org regexp anchored; also used to verify SBOMs in step 2a
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
status_page: https://status.chainguard.dev/incident/1130384   # this incident's page, as the KB links it
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

## Step 1: Inventory every place a Chainguard image or PHP package is used (read-only)

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

# Builds that install PHP themselves: Dockerfiles, apko configs and apko lockfiles. Match the package name
# alone, because `apk add` is often continued over several lines; read the surrounding lines.
PHP_PKG_RE='(^|[^A-Za-z0-9.-])php-8[.][0-9]+([^0-9]|$)'
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE "$PHP_PKG_RE" {} +
grep -rnE "$PHP_PKG_RE" <paths> --include='*.yaml' --include='*.yml' --include='*.lock.json' --include='*.tf'

# Builds that copy PHP out of another stage
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE 'COPY[[:space:]]+--from=.*(php|libphp|frankenphp)' {} +

# PHP configuration kept in the repo, for step 3b
find <paths> -type f \( -name 'php.ini*' -o -name '*.ini' -o -name 'php-fpm.conf*' -o -name 'www.conf*' \) \
  -exec grep -nHE '^[[:space:]]*(session\.upload_progress\.enabled|session\.serialize_handler|catch_workers_output|cgi\.fix_pathinfo|pm\.status_path)' {} +
grep -rnE 'session\.upload_progress\.enabled|PHP_INI|PHP_ADMIN_VALUE|PHP_VALUE' <paths> --include='*.yaml' --include='*.yml'

# Running pods, including init and ephemeral containers (imageID = the digest the node pulled)
kubectl get pods -A -o json | jq -r '.items[] | .metadata as $m
  | ((.status.initContainerStatuses // []) + (.status.containerStatuses // []) + (.status.ephemeralContainerStatuses // []))[]
  | [$m.namespace, $m.name, .image, .imageID] | @tsv'
# Workload specs, which catch Jobs and CronJobs with no live pod
kubectl get deploy,sts,ds,job,cronjob -A -o json | jq -r '.items[] | .kind as $k | .metadata as $m
  | (.spec.jobTemplate.spec.template.spec // .spec.template.spec)
  | ((.initContainers // []) + (.containers // []))[] | [$k, $m.namespace, $m.name, .image] | @tsv'
```

Helm values often split an image across `registry`, `repository`, `tag` and `digest` fields, sometimes with a global registry. When a grep match has no tag or digest, read the neighbouring lines (and any global registry) and join them into the full reference before step 2. `chainctl images discover` does this for you.

Deduplicate by image and digest. Don't filter by image name. Many images contain PHP without being named for it (`php_dependents` lists the Chainguard packages that depend on PHP), so check **every** Chainguard image.

## Step 2: Find PHP in each image (read-only)

First decide, for each image, whether **Chainguard built it** or the **user built it**:
- Chainguard-built: it's in `cgr.dev/chainguard/...` or `cgr.dev/$ORG/...`, or it's a mirror copy whose digest matches the digest at `cgr.dev/$ORG` (compare `crane digest` on both).
- The user's own build: a different digest (derived images, `apk add` or apko builds, mirrors rebuilt rather than copied). Its `crane config` history shows the user's build steps.

Use **2a for Chainguard-built images** and **2b for the user's own builds**. That way a verification failure in 2a really does mean something is wrong.

Resolve tags to digests (`crane digest REF`). Then read the packages using the first method that works.

**2a. Signed SBOM attestation (Chainguard-built images).** Resolve the platform digest the workload runs, check whether an SBOM attestation exists, and read it **only through signature verification**: `cosign download attestation` doesn't check signatures, and a mirror or registry the user controls could serve anything. Set the verification flags with `set --` to the issuer and identity flags from `signature_verify` (`public` for `cgr.dev/chainguard/...`; `org_registry`, with the identities from step 0, for `cgr.dev/$ORG/...`). The block is plain POSIX `sh`. It prints every package that carries PHP code (`sbom_php_rule`), each extension and SAPI on its own line:

```sh
PLAT=linux/amd64   # the platform the workload runs on (linux/arm64 too, if used)
PHP_RE='^php-8[.][0-9]+(-frankenphp)?(-[a-z0-9_]+)?$'
PHP_SKIP='(-config|-doc|-pear|-src|-frankenphp-dev)$'
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
        | jq -r --arg re "$PHP_RE" --arg skip "$PHP_SKIP" '.predicate.packages[]
            | select(any(.externalRefs[]?; .referenceLocator | startswith("pkg:apk/")))   # skip upstream source entries
            | select((.name | test($re)) and (.name | test($skip) | not))
            | select((.name | capture("^php-(?<b>8[.][0-9]+)").b) as $b | .versionInfo | startswith($b + "."))   # drops PECL extensions with their own versions
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

- `sbom: found, verified` plus package lines: rate them in step 3.
- `sbom: found, verified`, `packages: N` with N above 0, and no package lines: the image has no Chainguard package with PHP code. Rate it `NOT AFFECTED` (the rule was tested against every package in Chainguard's repositories). If `packages:` is 0 or missing, the SBOM wasn't read; use 2b.
- `sbom: found, NOT verified`: **stop** for this image (ground rule 8). It's a Chainguard-built image whose SBOM doesn't verify against Chainguard's identity. Don't mark it `UNKNOWN` and continue with 2b; report it and point the user to Support.
- `sbom: error`: cosign couldn't read the image, usually auth, network or a wrong reference. **Stop** for this image: ask the user to check access (for example `chainctl auth configure-docker`) and re-run 2a. Don't fall back to 2b, which would hit the same problem.
- `sbom: none`: there's no attestation to read. That's unusual for a Chainguard-built image (re-check that it really is one). Use 2b and say so in the report.

**2b. The image's filesystem (the user's own builds, and the fallback).** Use it for images the user built (derived images, `apk add` and apko builds, mirrors rebuilt rather than copied), even if they carry an SBOM of their own, which won't list a PHP copied in from a build stage. Also use it when 2a prints `sbom: none`. This doesn't run the image, and works on single- and multi-arch references. It reports three things: whether there's an apk database, the PHP packages it lists, and any PHP binary on disk with the PHP version compiled into it. It also keeps the image's PHP configuration for step 3b:

```sh
PHP_RE='^php-8[.][0-9]+(-frankenphp)?(-[a-z0-9_]+)?$'
PHP_SKIP='(-config|-doc|-pear|-src|-frankenphp-dev)$'
echo "arch: $(crane config --platform "$PLAT" "$REF" | jq -r '.architecture')"   # must match the workload's platform
FS=$(mktemp)     # needs disk space roughly twice the size of the image: the export, then its unpacked files
CONF=$(mktemp -d)  # the image's PHP configuration, kept for step 3b; remove it when done
if ! crane export --platform "$PLAT" "$REF" - > "$FS" || [ ! -s "$FS" ]; then
  echo "export: error"   # stop for this image: an empty export would look like "no PHP"
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
      awk -F: -v re="$PHP_RE" -v skip="$PHP_SKIP" '
        /^P:/ {p = substr($0, 3)}
        /^V:/ {v = substr($0, 3)
               if (p ~ re && p !~ skip && match(p, /^php-8[.][0-9]+/) && index(v, substr(p, 5, RLENGTH - 4) ".") == 1)
                 print "package:", p, v}' "$X/$DB" | sort -u
    else
      echo "apk-db: none"
    fi
    # PHP code on disk, whether or not a package owns it. Every PHP binary carries the engine banner
    # ("Zend Engine vX.Y.Z, Copyright ..."); FrankenPHP has no engine of its own but carries the compile-time
    # "X-Powered-By: PHP/" string and imports php_request_startup. Scanners and fingerprinting tools that know
    # the header string have neither, so they don't match.
    LC_ALL=C grep -rlaE 'Zend Engine v[0-9]|X-Powered-By: PHP/[0-9]' "$X" 2>/dev/null | while read -r b; do
      [ "$(head -c 4 "$b" | od -An -c | tr -d ' ')" = '177ELF' ] || continue   # ELF files only
      PV=$(LC_ALL=C grep -aoE 'X-Powered-By: PHP/[0-9]+[.][0-9]+[.][0-9]+' "$b" | sed 's#.*/#php/#' | sort -u | tr '\n' ' ')
      if LC_ALL=C grep -qaE 'Zend Engine v[0-9]+[.][0-9]+[.][0-9]+, Copyright' "$b"; then
        echo "php-engine: /${b#"$X"/} ${PV}"
      elif LC_ALL=C tr '\000' '\n' < "$b" | LC_ALL=C grep -qx 'php_request_startup'; then
        echo "php-sapi: /${b#"$X"/} built against ${PV}"
      fi
    done
    # Keep the PHP configuration for step 3b
    for d in etc/php usr/local/etc/php etc/php-fpm.d; do
      [ -e "$X/$d" ] && mkdir -p "$CONF/$(dirname "$d")" && cp -R "$X/$d" "$CONF/$d"
    done
    echo "config: $CONF"
  fi
  chmod -R u+w "$X" 2>/dev/null; rm -rf "$X"
fi
rm -f "$FS"
```

This exports and unpacks the image's whole filesystem, so it's slower and needs disk space for large images. If `arch` isn't the platform the workload runs on, the image doesn't have that platform and crane exported a different one: report it and check the reference the workload actually pulls.

What the lines look like (from Chainguard packages):

```
package: php-8.5 8.5.13-r1
package: php-8.5-pdo 8.5.13-r1
php-engine: /usr/bin/php php/8.5.13
php-engine: /usr/bin/php-fpm php/8.5.13
php-engine: /usr/lib/php/libphp.so php/8.5.13                      # php-8.5-frankenphp
php-sapi: /usr/bin/frankenphp built against php/8.5.12             # frankenphp-8.5 on a fixed image: expected
```

Interpreting the result:
- **`export: error` or `unpack: error`:** stop for this image and check access, as for `sbom: error`.
- **`package` or `php-engine` lines:** rate each one in step 3. PHP installed from a package shows up as both a `package` line and a `php-engine` line; that's one finding, not two.
- **`php-sapi` lines:** never rate these. They're FrankenPHP; the PHP it runs is the `libphp.so` next to it (a `php-engine` line) or the `php-8.N-frankenphp` package.
- **None of these:** `NOT AFFECTED`.
- Distroless Chainguard bases such as `glibc-dynamic` and `static` still have an apk database, so an empty package list alone proves nothing; the `php-engine` check is what catches a PHP copied in from a build stage.
- For mirrored images, read from the mirror. If the mirror has no attestation, 2b on the mirror is the authoritative check of what you actually run.

## Step 3: Compare versions exactly (read-only)

**Never compare version strings as text** (`8.4.28-r0` vs `8.4.28-r10`). Use apk's own comparator:

```sh
docker run --rm cgr.dev/chainguard/wolfi-base apk version -t "<installed>" "<fixed>"   # prints <, = or >
```

Rate each finding from step 2 with the first rule that applies:

1. **A package line** (from 2a or 2b). Map the name to its origin (`sbom_php_rule`), then:
   - origin in `end_of_life`: `END OF LIFE`. This release has no fixed php-8.1 build; step 4 proposes the upgrade.
   - origin in `fixed_versions`: `PATCHED` at or above the fixed version. Below it: `VULNERABLE`. Rate **every** package line: if `php-8.4` is fixed but `php-8.4-pdo` isn't, the image is `VULNERABLE`; name the package in the Action column.
   - in none of these (an origin newer than 8.6): `UNKNOWN`, with "not in this skill's data" in the Action column. Check the KB, or ask Support.
2. **A `php-engine` line that no package line explains** (a PHP copied in, built from source or unpacked from a tarball): take the branch from the version (`php/8.4.27` is branch 8.4). Branch 8.1 or older: `END OF LIFE`. A branch in `upstream_fixed`: `PATCHED` at or above it, noted "by binary version"; below it, `VULNERABLE`. Any other branch, or no version on the line: `UNKNOWN`. The version is a valid test here because the fixes are PHP's own releases (fact 2), so this doesn't apply to a binary built from patched sources of your own.
3. **A `php-sapi` line:** not rated (step 2b). If no `php-engine` line or `php-8.N-frankenphp` package explains which PHP it runs, the image is `UNKNOWN`.

The `frankenphp-8.N` package itself (version 1.13.5) is FrankenPHP, not PHP: don't rate it against `fixed_versions`.

Then, one status per image, the first that applies:

| Status | When |
|---|---|
| `UNKNOWN` | 2a or 2b couldn't be read, or any finding rated `UNKNOWN` |
| `END OF LIFE` | any finding rated `END OF LIFE` |
| `VULNERABLE` | any finding rated `VULNERABLE` |
| `PATCHED` | every finding rated `PATCHED` |
| `NOT AFFECTED` | no PHP package and no `php-engine` line |

After step 4, a `VULNERABLE` Chainguard-built image whose fix isn't in the user's registry yet becomes `WAITING ON CHAINGUARD`.

**Dockerfiles with no built image to inspect:** rate them from their pins and base images. An `apk add` pin below the fixed version is `VULNERABLE`. Otherwise check each `FROM` image with steps 2–3, including any build stage PHP is copied from, and check the image the Dockerfile produces once it's built.

**apko configs and lockfiles:** the lockfile decides the version, but **only if the build passes `apko build --lockfile …`**; apko doesn't pick it up on its own, so check the Makefile or CI. Read the locked versions per architecture with the same rule as 2a:

```sh
jq -r --arg re "$PHP_RE" --arg skip "$PHP_SKIP" '.contents.packages[]
  | select((.name | test($re)) and (.name | test($skip) | not))
  | select((.name | capture("^php-(?<b>8[.][0-9]+)").b) as $b | .version | startswith($b + "."))
  | "\(.name) \(.version) \(.architecture)"' apko.lock.json
```

Any entry below the fixed version is `VULNERABLE` (note "by lock"). Without a lockfile in use, an exact pin (`php-8.4=8.4.27-r0`) below the fixed version is `VULNERABLE` (note "by pin"); a fuzzy pin (`~`) or an unpinned package resolves at build time, so check the built image.

## Step 3b: Check which CVEs apply (read-only)

Do this for every image that isn't `NOT AFFECTED`. It doesn't change the status; it tells the user how urgent each image is and which stopgap in step 6 applies. For a `PATCHED` image, only the explicit-setting check in item 2 applies: an explicit `On` overrides the fixed releases' default of off (KB step 6, GHSA-658j-r8rw-q6mx). List each one under Open items.

1. **By what's installed.** Each CVE's `component` (in `cves`) and its branch decide whether it can apply. `where_the_code_is` maps the component to a package: a CVE whose component isn't installed is `not applicable` to that image (for example, the FPM CVEs on an image without `php-8.N-fpm`, or the SOAP CVEs on a FrankenPHP image). The `built_in` components apply wherever PHP runs. A CVE whose `branches` don't include the image's branch is `not applicable` too.
2. **CVE-2026-115560 (session serializer mismatch).** It needs session upload progress on, a writer using the `php_binary` or `php_serialize` serializer and a reader of the same session store using `php` (PHP's advisory, GHSA-658j-r8rw-q6mx). Read the configuration from step 1 and from 2b (`config:`): look for `session.upload_progress.enabled` in `php.ini` and `conf.d/*.ini`, and in `php_admin_value`/`php_value` lines of FPM pool files. Report `on (explicitly set)`, `on (default for this version)` when nothing sets it on a vulnerable build (see `defaults`), or `off`. An explicit `On` keeps it on after the update too: point it out, and tell the user that every reader and writer of a session store it can reach must then use the same `session.serialize_handler`, because the fix doesn't enforce that across separate configurations (PHP's advisory). Also report any `session.serialize_handler` settings found.
3. **CVE-2026-129291 (FPM epoll use-after-free).** PHP's advisory says it needs local code execution in an FPM worker, `catch_workers_output` on, and the epoll event backend; a root FPM master allows escalation to root. Chainguard's `php-8.N-fpm-config` turns `catch_workers_output` on (`defaults`). Report the image's user (`crane config` `.config.User`) next to it.

Report applicability next to the status (see Report format), never instead of it. Show the user the inventory table now before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

For **images Chainguard builds** (catalog, Custom Assembly and custom images), first check whether a patched build exists **in the user's registry**: resolve the tag's current digest and repeat steps 2–3 on it. If it's still vulnerable, go to step 6 for that image. To list newer builds of a tag in an org registry: `chainctl images history IMAGE:TAG --parent $ORG`. For **images the user builds**, the fix is a rebuild (rows below), not Support.

To tell a mirror copy from the user's own build: a mirror copy has the same digest as the image in `cgr.dev/$ORG` (compare `crane digest` on both); the user's own build has a different digest, and its `crane config` history shows their build steps.

| How it's referenced | Proposed change |
|---|---|
| By tag (`:8.4`), and the tag now points to a patched digest | Propose pinning the reference to the digest you verified in steps 2–3 and 5 (`IMAGE:TAG@sha256:…`), then roll out (step 7). A restart alone can reuse a cached image (`imagePullPolicy: IfNotPresent`), and the tag can move after you verified it. |
| By `:latest` on php, php-fips, laravel or renovate | `latest` now resolves to PHP 8.6.0 (KB), a new PHP stream with the fixes. Say so before proposing the new digest; if the user isn't ready for 8.6, propose a version tag such as `php:8.5` instead, pinned to its verified digest. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror | Propose copying the **verified digest**, not the tag (which can move): `cosign copy cgr.dev/$ORG/IMAGE@sha256:<verified> <mirror>/IMAGE:TAG`. This copies signatures and attestations too. Then compare digests on both sides. |
| Via a pull-through cache (Artifactory remote repo, Harbor proxy cache) | These can't receive a push. Propose refreshing or expiring the cached tag, or referencing the verified digest, which the cache will fetch. |
| Derived image (`FROM cgr.dev/...`) | If the `FROM` line is pinned by digest, first propose bumping it to a verified, patched digest (show the diff): rebuilding a pinned base rebuilds the same vulnerable image. Then rebuild with `--pull --no-cache`, push, and update references to the new image. Verify the rebuilt image with steps 2–3: it has no Chainguard attestation, so step 2b applies. |
| PHP copied from a build stage | The copy keeps the version of the stage it came from; updating the final stage's base image doesn't change it. Propose bumping the **build stage** (its `FROM`, or its `apk add` pins) to a patched version, then rebuild with `--pull --no-cache` and verify with step 2b. |
| Dockerfile or apko config with `apk add` of PHP packages | Raise or remove old pins and fail closed, for example `apk add --no-cache 'php-8.4>=8.4.28-r0' 'php-8.4-fpm>=8.4.28-r0'`. Raise **every** `php-8.4-*` subpackage it installs to the same version; a pin left on one extension keeps the image vulnerable. Rebuild with `--pull --no-cache`, then verify the result with steps 2b–3. For apko, regenerate the lockfile with `apko lock`; that moves **every** package, so show the whole lockfile diff for approval. If a policy blocks the new versions, tell the user to contact their org admin or Support; don't change policy yourself. |
| Custom Assembly image | These rebuild automatically unless the configuration pins PHP package versions. If your chainctl has it, read the pins with `chainctl images overlays list --parent "$ORG" -o json` (packages under `.overlays[].config.contents.packages`; check the output's shape before relying on it). Otherwise ask the user to check the configuration in the Chainguard Console. Propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| `php-8.1` (`end_of_life`) | This release has no fixed php-8.1 build; PHP 8.1 is end of life upstream. Propose an upgrade plan to 8.2 or later, checking the application's compatibility; don't change anything automatically. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block, substituting `IMAGE@DIGEST`. Use `public` for `cgr.dev/chainguard/...` and `org_registry` for `cgr.dev/$ORG/...`. Images the user builds themselves aren't signed by Chainguard; verify them with the user's own signing policy, if any. For a mirror, verify the `cgr.dev` digest you copied from, or the mirror copy if it was made with `cosign copy`.

For the org registry, use the org's two signing identities from step 0.

**Check both values before running cosign.** Each must be a non-empty identity of the form `<hex>/<hex>`, not empty and not `null`. cosign matches `--certificate-identity-regexp` anywhere in the certificate subject, so an empty alternative in `(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})` would accept a signature from *any* `issuer.enforce.dev` identity. If one value is missing, drop it from the group (for example `(${IMAGE_SYNCER})`). If both are missing, stop: report it, and point the user to Support.

If verification fails for an image, **stop**: don't deploy that image; report it and point the user to Support. Never retry with a looser identity or issuer.

## Step 6: If the fix isn't in the user's registry yet, or the user can't update yet

Patched images reach customer registries automatically after Chainguard publishes them; this can take additional time.

- Report the image, tag and digest as `WAITING ON CHAINGUARD`, and help the user open a Support request at https://support.chainguard.dev, including the image, tag, digest and the PHP package versions from step 2.
- Don't switch the user to public images or another registry as a workaround; that's a Support decision.

If the user can't update yet, offer the stopgap that matches step 3b. **It doesn't replace the update**: say so, and say what it leaves open. It's a configuration change: show the diff and wait for approval (ground rule 2).

| CVE | Stopgap | What it leaves open |
|---|---|---|
| CVE-2026-115560 | Set `session.upload_progress.enabled=0` in every PHP configuration that can write to the affected session store (PHP's advisory and the KB): in `php.ini`, a `conf.d` file or the FPM pool, before request input is processed. Calling `ini_set()` from the application is too late. | The other 16 CVEs. After the update, an explicit `On` still turns it back on. |
| CVE-2026-126714 | The same setting. PHP's advisory lists it as a temporary, partial measure (KB step 6). | Applications that store attacker-controlled session data themselves; the other 16 CVEs. |
| CVE-2026-129291 | Set `catch_workers_output = no` in affected FPM pools (PHP's advisory, a temporary workaround). `php-8.N-fpm-config` sets it to `yes` (`defaults`). | The use-after-free itself; the other 16 CVEs. Running the FPM master as non-root, as the `-fpm` tags of the php image do by default, limits what an attacker gains but doesn't fix it. |

## Step 7: Apply approved changes and roll out

- Make only the approved edits. Commit on a branch and open a PR if the repo uses one.
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`), with the references pinned to verified digests. Don't rely on `kubectl rollout restart` for tag references: nodes that cached the tag keep running the old image. Running containers don't update themselves, and reloading PHP-FPM doesn't replace the running binary.
- Sync mirrors before redeploying anything that pulls from them.

## Step 8: Re-verify and report

1. Re-run the step 1 `kubectl` query and confirm every affected workload now runs a `PATCHED` digest (repeat steps 2–3 on the running `imageID`s, not just the manifests).
2. Re-run the explicit-setting check of step 3b item 2 on each image now `PATCHED`, and list any explicit `session.upload_progress.enabled = On` under Open items, with the `session.serialize_handler` settings found.
3. Scanners: Chainguard's advisory data records these CVEs as fixed (`advisories`), and the feeds in `scanner_feeds` list them at the versions in `fixed_versions`. A scanner that reads these feeds should flag the older versions once its database is refreshed (for grype: `grype db update`); refresh it and rescan. A clean scan doesn't replace steps 2–3. If a scanner still flags one of these CVEs on an image step 3 rated `PATCHED`, confirm it reads a feed in `scanner_feeds`, and contact Support with the image digest and scanner version.
4. Produce the final report.

### Report format

```
Chainguard PHP security release 2026-11-19 (17 CVEs; PHP 8.2.36, 8.3.37, 8.4.28, 8.5.13) — remediation report (<date, UTC>)

| Where used (file:line / ns/workload) | Image reference | Digest | PHP found (packages / binaries) | Status | Applies (step 3b) | Action taken / proposed |
|---|---|---|---|---|---|---|
| k8s web/app-7f9 | cgr.dev/acme/php:8.4 | sha256:… | php-8.4 8.4.27-r0, php-8.4-fpm 8.4.27-r0 | VULNERABLE → PATCHED | engine, session, FPM (catch_workers_output on, runs as nonroot) | pinned verified digest with 8.4.28-r0 (approved 14:02) |
| web/Dockerfile:3 | registry.corp/web:2.1 | sha256:… | php-8.2 8.2.36-r0, php-8.2-pdo 8.2.35-r0 | VULNERABLE | engine, session | php-8.2-pdo pinned at 8.2.35-r0 in web/Dockerfile:4; raise the pin (proposed) |
| k8s api/franken-0 | cgr.dev/acme/frankenphp:8.5 | sha256:… | php-8.5-frankenphp 8.5.13-r0 | PATCHED | n/a | none (startup log shows php_version 8.5.12: expected) |

Summary: N references checked · patched · not affected · vulnerable · end of life · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses (from step 3, plus step 4's `WAITING ON CHAINGUARD`): `PATCHED`, `NOT AFFECTED`, `VULNERABLE`, `END OF LIFE`, `UNKNOWN`, `WAITING ON CHAINGUARD`. Put the reason in the Action column (for example "pin in web/Dockerfile:4", "by binary version" or "copied from build stage `build`"), not in the status.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| FrankenPHP's `FrankenPHP started` log shows a `php_version` from the previous release on a fixed image | Expected: that field is the PHP version FrankenPHP was compiled against (`frankenphp`); the `X-Powered-By` header and `php -v` show the running version. Decide from the `php-8.N-frankenphp` package (steps 2–3) |
| `php` is fixed, but the image is still rated vulnerable | An extension or SAPI subpackage is still at the previous version: an `apk add` pin, a lockfile, or an image rebuilt before every subpackage was published. Raise the pin or take a newer digest (step 4) |
| A scanner shows none of these CVEs on an image step 3 rated `VULNERABLE` | Stale scanner database, or a scanner that doesn't read `scanner_feeds` → refresh it (step 8); rely on steps 2–3 |
| Scanner still reports the CVEs on a patched image | Stale scanner DB or wrong feed → refresh, confirm `scanner_feeds`; re-check the version with steps 2–3 |
| `session.upload_progress.enabled` is still on after the update | An explicit setting in `php.ini`, `conf.d` or an FPM pool overrides the new default of off |
| `php-8.1` has no fixed version | End of life upstream (`end_of_life`) → upgrade to 8.2 or later |
| `php:latest` (or `php-fips:latest`, laravel, renovate) moved to PHP 8.6 | Expected: images that track the newest PHP release now use 8.6.0, which also has the fixes. If the application isn't ready for 8.6, use a version tag such as `php:8.5` (KB) |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, a cached tag (`imagePullPolicy: IfNotPresent`), or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned PHP package version in its configuration (step 4) |
| Own build still installs an old PHP | Cached layer or an old `apk add` pin → `--pull --no-cache`, raise every PHP pin |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the PHP package versions from step 2, and this report. Status updates: https://status.chainguard.dev/incident/1130384.
