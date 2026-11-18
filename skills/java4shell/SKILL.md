---
name: java4shell
description: >-
  Find, verify and remediate Chainguard images and packages affected by
  Oracle's November 2026 Critical Security Patch Update for Java SE, including
  CVE-2026-114938, known as Java4Shell (unauthenticated RCE in OpenJDK 17, 21,
  25 and 27). Covers
  OpenJDK 8, 11, 17, 21, 25 and 27, FIPS and vendor JDKs such as Corretto,
  images with an embedded Java runtime (ontop, kafka-native) and runtimes you
  build yourself with jlink or copy between build stages. Inventories image
  references in repos and running Kubernetes workloads, reads each image's SBOM
  and filesystem for Java, proposes and (with approval) applies fixes, then
  re-verifies. Use when the user mentions Java4Shell, CVE-2026-114938, Oracle's November
  2026 Java update, Chainguard's OpenJDK advisory, or asks "are we patched?".
---

# Remediate Java4Shell (CVE-2026-114938) and Oracle's November 2026 Java SE update in Chainguard images

Published by Chainguard for its customers. This skill implements the steps in Chainguard's KB article *"ACTION REQUIRED: Update Chainguard images with OpenJDK for Oracle's November 2026 Critical Security Patch Update"* so an agent can carry them out in your environment. The human-readable KB remains the authority: if anything here disagrees with it, follow the KB and tell the user.

Three facts shape everything below:

- **One update, many CVEs, one fix per Java line.** Oracle's update fixes several Java SE vulnerabilities at once. CVE-2026-114938 affects Java 17, 21, 25 and 27; Java 8 and 11 are affected by others in the same update. Each fixed package fixes all of them for its line, so decide from the Java version, not from which CVE a scanner names.
- **Some images don't list Java in their SBOM.** Images with an embedded runtime (a jlinked JRE, or a GraalVM native executable) and images you build yourself with jlink or by copying a JDK between build stages carry Java that no OpenJDK package records. Step 2b finds them on the filesystem.
- **Versions have four or five parts.** Fixed builds are numbered like `17.0.21.1` (OpenJDK) and `17.0.21.1.2` (Corretto). Compare with apk's comparator (step 3), never as text.

## Ground rules for the agent (read first, follow always)

1. **Discovery and verification are read-only.** Run them freely.
2. **Every change needs the user's explicit approval first**: editing files, pushing or copying images, building, deploying, restarting workloads, changing policies or JVM options. Show the exact diff or command, say what it affects, and wait for a yes. Approval for one change does not carry over to the next.
3. **Prefer the user's own change process.** If manifests live in Git (GitOps, Helm, Terraform), propose a branch or PR instead of changing a cluster directly. Ask before touching production.
4. **Never weaken security to make progress.** No skipping signature verification, no `--insecure` or `--allow-insecure-registry`, no disabling admission policies, no pinning *older* versions.
5. **Don't handle credentials.** If a registry, cluster or `chainctl` isn't authenticated, ask the user to log in themselves. Never print tokens or secrets.
6. **Report uncertainty instead of guessing.** If an image's SBOM or filesystem can't be read, mark it `UNKNOWN`, never "patched".
7. **Never try to trigger the bugs.** Don't send crafted input or run exploit code against any image or service to "test" it. Verification is by version only.
8. **Stop and escalate** if a patched version isn't available in the user's registry (step 6), or a signature fails to verify.

## Incident data (single source of truth: update this block for later rounds)

```yaml
update: Oracle Critical Security Patch Update, November 2026 (released 2026-11-17)
headline_cve: CVE-2026-114938      # hotspot/compiler, CVSS v3.1 8.1; Java 17, 21, 25 and 27 only
cves_by_line:                      # OpenJDK risk matrix (disclosure.openjdk); a fixed package fixes every CVE for its line
  "8": [CVE-2026-114939, CVE-2026-114940, CVE-2026-114943, CVE-2026-114944, CVE-2026-114946]
  "11": [CVE-2026-114939, CVE-2026-114940, CVE-2026-114943, CVE-2026-114944, CVE-2026-114946]
  "17": [CVE-2026-114938, CVE-2026-114939, CVE-2026-114940, CVE-2026-114942, CVE-2026-114943, CVE-2026-114944,
         CVE-2026-114945, CVE-2026-114946]
  "21": [CVE-2026-114938, CVE-2026-114939, CVE-2026-114940, CVE-2026-114941, CVE-2026-114942, CVE-2026-114943,
         CVE-2026-114944, CVE-2026-114945, CVE-2026-114946]
  "25": [CVE-2026-114938, CVE-2026-114939, CVE-2026-114940, CVE-2026-114941, CVE-2026-114942, CVE-2026-114943,
         CVE-2026-114944, CVE-2026-114945, CVE-2026-114946, CVE-2026-114947]
  "27": [CVE-2026-114938, CVE-2026-114939, CVE-2026-114940, CVE-2026-114941, CVE-2026-114942, CVE-2026-114943,
         CVE-2026-114944, CVE-2026-114945, CVE-2026-114946, CVE-2026-114947]
advisories: {}                     # DRAFT: CVE -> CGA ID, from the KB
disclosure:
  oracle: https://www.oracle.com/security-alerts/cspunov2026.html
  openjdk: https://openjdk.org/groups/vulnerability/advisories/2026-11-17
fixed_versions:                    # apk origin package -> first fixed version ("this version or later")
  openjdk-8: 8.514-r0
  openjdk-11: 11.0.33.1-r0
  openjdk-17: 17.0.21.1-r0
  openjdk-21: 21.0.13.1-r0
  openjdk-25: 25.0.5.1-r0
  openjdk-27: 27.0.1.1-r0
  openjdk-fips-25: 25.0.5.1-r0
  openjdk-fips-27: 27.0.1.1-r0
  openjdk-jipher-fips-25: 25.0.5.1-r0
  openjdk-jipher-fips-27: 27.0.1.1-r0
  corretto-8: 8.514.01.1-r0
  corretto-11: 11.0.33.1.1-r0
  corretto-17: 17.0.21.1.2-r0
  corretto-21: 21.0.13.1.2-r0
  corretto-25: 25.0.5.1.2-r0
  corretto-27: 27.0.1.1.4-r0
  corretto-fips-25: 25.0.5.1.2-r0
  corretto-fips-27: 27.0.1.1.4-r0
  corretto-jipher-fips-25: 25.0.5.1.2-r0
  corretto-jipher-fips-27: 27.0.1.1.4-r0
  cof-corretto-17: 17.0.21.1.2-r0
  cof-corretto-21: 21.0.13.1.2-r0
  cof-corretto-25: 25.0.5.1.2-r0
  cof-corretto-27: 27.0.1.1.4-r0
  adoptium-openjdk-17: 17.0.21.9.1.0.2-r0
  adoptium-openjdk-21: 21.0.13.9.1.0.2-r0
  adoptium-openjdk-25: 25.0.5.8.1.0.2-r0
  adoptium-openjdk-27: 27.0.1.9.1.0.4-r0
  adoptium-openjdk-fips-25: 25.0.5.8.1.0.2-r0
  adoptium-openjdk-fips-27: 27.0.1.9.1.0.4-r0
  adoptium-openjdk-jipher-fips-25: 25.0.5.8.1.0.2-r0
  adoptium-openjdk-jipher-fips-27: 27.0.1.9.1.0.4-r0
  zulu-8-cpu: 8.0.513-r0             # Zulu: Azul binaries, from Azul's November 2026 release notes
  zulu-8-psu: 8.0.514-r0
  zulu-11-cpu: 11.0.32.1.201-r0
  zulu-11-psu: 11.0.33.1-r0
  zulu-17-cpu: 17.0.20.1.201-r0
  zulu-17-psu: 17.0.21.1-r0
  zulu-21-cpu: 21.0.12.1.201-r0
  zulu-21-psu: 21.0.13.1-r0
  zulu-25-cpu: 25.0.4.1.201-r0
  zulu-25-psu: 25.0.5.1-r0
  zulu-27-psu: 27.0.1.1-r0
pending:                           # affected, no fixed build yet: the newest build known to be vulnerable
  adoptium-openjdk-11: 11.0.33.5-r4
  adoptium-openjdk-8: 8.512.5-r3
  alibabadragonwell-dragonwell-8: 8.502.30.29-r0
  graalvm-25: 25.0.4.1-r11
  graalvm-25.1: 25.1.3-r9
  graalvm-25.2: 25.2.4-r7
  graalvm-25.3: 25.3.4.1-r1
  graalvm-25.4: 25.4.4.1.1-r2
  graalvm-25.5: 25.5.5.0.3-r1
  liberica-17: 17.0.21.12-r2
  liberica-21: 21.0.13.12-r0
  liberica-25: 25.0.5.11-r3
  liberica-27: 27.0.1.11-r0
  liberica-8: 8.472.11-r3
  mandrel-25.0: 25.0.5.1-r1
  openjdk-11-openj9: 0.61.0-r4
  openjdk-17-openj9: 0.63.0-r0
  openjdk-21-openj9: 0.63.0-r0
  openjdk-25-openj9: 0.63.0-r0
  openjdk-8-openj9: 0.61.0-r8
  openjdk-crac-17: 17.0.21.9-r0
  openjdk-crac-21: 21.0.13.9-r1
  openjdk-crac-25: 25.0.5.8-r1
no_fix:                            # no fixed build will ship for these: move to a supported Java line
  discontinued: [openjdk-7, openjdk-9, openjdk-10, openjdk-12, openjdk-13, openjdk-15, openjdk-16, openjdk-18,
                 openjdk-19, openjdk-20, openjdk-22, openjdk-23, openjdk-24, corretto-24, cof-corretto-24,
                 liberica-24, graalvm-23, graalvm-24, openjdk-11-bcfips]   # no longer built
  java_26: [openjdk-26, openjdk-fips-26, openjdk-jipher-fips-26, openjdk-26-openj9, adoptium-openjdk-26,
            adoptium-openjdk-fips-26, corretto-26, corretto-fips-26, cof-corretto-26, liberica-26, zulu-26-psu]
            # DRAFT: KB section 6. OpenJDK 26 receives no further updates upstream
subpackages: >-
  A subpackage carries its origin's version. Map an SBOM or apk name to its origin: first look it up in
  `aliases`, otherwise take the longest key in fixed_versions, pending or no_fix that equals the name or is
  followed by "-" (openjdk-17-jre and openjdk-17-default-jdk map to openjdk-17; zulu-17-psu-jre maps to
  zulu-17-psu).
aliases:                           # subpackage names that don't start with their origin's name
  openjdk-11-jre-bcfips: openjdk-11-bcfips
  openjdk-11-jre-base-bcfips: openjdk-11-bcfips
  openjdk-11-default-jvm-bcfips: openjdk-11-bcfips
upstream_fixed:                    # for a runtime no package records: compare its JAVA_VERSION (step 3)
  "8": "8.514"                     # JAVA_VERSION="1.8.0_514" -> compare as 8.514
  "11": "11.0.33.1"
  "17": "17.0.21.1"
  "21": "21.0.13.1"
  "25": "25.0.5.1"
  "27": "27.0.1.1"
zulu_cpu_fixed:                    # Azul's CPU builds keep the previous update's JAVA_VERSION (step 3)
  "8": "8.513"                     # JAVA_VERSION="1.8.0_513"
  "11": "11.0.32.1.201"
  "17": "17.0.20.1.201"
  "21": "21.0.12.1.201"
  "25": "25.0.4.1.201"
sbom_jdk_regex: '^((openjdk|corretto|cof-corretto|zulu|liberica|adoptium-openjdk|alibabadragonwell-dragonwell)(-(fips|crac|jipher-fips))?-[0-9]+|graalvm-[0-9]+([.][0-9]+)?|mandrel-[0-9]+([.][0-9]+)?)(-[a-z0-9-]+)?$'
embedded_runtimes:                 # Chainguard packages that carry their own Java; the SBOM lists the package, not a JDK
  # vulnerable_through: the newest build known to carry a Java older than this update; fixed: the first build carrying this update's Java
  ontop: {java: "11", kind: jlink, path: /opt/java/openjdk, vulnerable_through: 5.5.0-r34, fixed: 5.5.0-r35}
  ontop-fips: {java: "11", kind: jlink, path: /opt/java/openjdk, vulnerable_through: 5.5.0-r29, fixed: 5.5.0-r30}
  kafka-native: {java: "25", kind: native, path: /usr/lib/kafka-native/kafka.Kafka, vulnerable_through: 4.4.0-r1}
  kates-native: {java: "25", kind: native, path: /usr/lib/kates-native/kates, vulnerable_through: 1.41.2-r0}
  truffleruby: {java: "25", kind: native library, path: /usr/share/truffleruby/lib/librubyvm.so, vulnerable_through: 34.0.1-r5}
  geoip-api: {java: "23", kind: native, path: /usr/bin/geoip-api, vulnerable_through: 2026.46-r0}
  sbt: {java: "23", kind: native, path: /usr/share/java/sbt/bin/sbtn-*, vulnerable_through: 2.1.0-r0}
  sbt-stage0: {java: "23", kind: native, path: /usr/share/java/sbt/bin/sbtn-*, vulnerable_through: 1.11.6-r4}
  scala-3.8: {java: "17", kind: native, path: /usr/share/scala/libexec/scala-cli, vulnerable_through: 3.8.4-r13}
  scala-3.9: {java: "17", kind: native, path: /usr/share/scala/libexec/scala-cli, vulnerable_through: 3.9.0-r3}
  scala-3.10: {java: "17", kind: native, path: /usr/share/scala/libexec/scala-cli, vulnerable_through: 3.10.1-r1}
  commercial-elasticsearch-9.4: {java: "25", kind: native, path: /usr/share/elasticsearch/lib/tools/server-launcher/server-launcher, vulnerable_through: 9.4.9-r0}
  commercial-elasticsearch-9.5: {java: "25", kind: native, path: /usr/share/elasticsearch/lib/tools/server-launcher/server-launcher, vulnerable_through: 9.5.6-r0}
  sonarqube: {java: "25", kind: native, path: /usr/share/sonarqube/elasticsearch/lib/tools/server-launcher/server-launcher, vulnerable_through: 26.11.0.134175-r0}
  emscripten: {java: "25", kind: native, path: /upstream/emscripten/node_modules/google-closure-compiler-linux/compiler, vulnerable_through: 6.0.9-r2}
  # DRAFT: which of these Chainguard rebuilds, and the fixed versions, from the KB
not_openjdk:                       # look like a JVM in step 2b but contain no OpenJDK code
  libgcj-6: "GCJ, the GNU Java runtime; its libjvm.so is not OpenJDK"
  starrocks-be: "lib/libjvm.so is a 6 KB stub (libmockjvm); StarRocks runs on the system JDK from JAVA_HOME"
known_affected_images:             # a hint only; always decide from steps 2-3. "+fips" = a -fips variant also exists
  jdk: [jdk, jre, adoptium-jdk, adoptium-jre, amazon-corretto-jdk]   # DRAFT: confirm against the KB list
  bundling: [elasticsearch (+fips), logstash (+fips)]               # DRAFT: confirm against the KB list
  embedded_runtime: [ontop, ontop-fips, kafka-native]               # DRAFT: confirm against the KB list
scanner_feeds:
  - https://packages.cgr.dev/chainguard/security.json
  - https://packages.wolfi.dev/os/security.json
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

## Step 1: Inventory every place a Chainguard image, JDK package or Java runtime is used (read-only)

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

# Builds that install a JDK themselves: Dockerfiles, apko configs and apko lockfiles. Match the package name
# alone, because `apk add` is often continued over several lines; read the surrounding lines. The boundary
# skips packages that only name a JDK, such as kafka-4.1-openjdk-21.
JDK_PKG_RE='(^|[^A-Za-z0-9.-])((openjdk|corretto|cof-corretto|zulu|liberica|adoptium-openjdk|alibabadragonwell-dragonwell)(-[a-z]+)*-[0-9]+|(graalvm|mandrel)-[0-9])'
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE "$JDK_PKG_RE" {} +
grep -rnE "$JDK_PKG_RE" <paths> --include='*.yaml' --include='*.yml' --include='*.lock.json' --include='*.tf'

# Builds that make their own runtime: jlink, native-image, or a JDK copied out of a build stage
find <paths> -type f \( -iname 'dockerfile*' -o -iname '*.dockerfile' -o -iname 'containerfile*' \) \
  -exec grep -nHE '\bjlink\b|\bnative-image\b|COPY[[:space:]]+--from=.*(/usr/lib/jvm|/opt/java|jre|jdk)' {} +

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

Deduplicate by image and digest. Don't filter by image name. Images that bundle Java (Elasticsearch, Logstash, Kafka, Keycloak and many more) are affected even though they're not named "jdk", so check **every** Chainguard image.

## Step 2: Read the Java versions from each image (read-only)

First decide, for each image, whether **Chainguard built it** or the **user built it**:
- Chainguard-built: it's in `cgr.dev/chainguard/...` or `cgr.dev/$ORG/...`, or it's a mirror copy whose digest matches the digest at `cgr.dev/$ORG` (compare `crane digest` on both).
- The user's own build: a different digest (derived images, `apk add` or apko builds, jlink or copied runtimes, mirrors rebuilt rather than copied). Its `crane config` history shows the user's build steps.

Use **2a for Chainguard-built images** and **2b for the user's own builds**. That way a verification failure in 2a really does mean something is wrong.

Resolve tags to digests (`crane digest REF`). Then read the versions using the first method that works.

**2a. Signed SBOM attestation (Chainguard-built images).** Resolve the platform digest the workload runs, check whether an SBOM attestation exists, and read it **only through signature verification**: `cosign download attestation` doesn't check signatures, and a mirror or registry the user controls could serve anything. Set the verification flags with `set --` to the issuer and identity flags from `signature_verify` (`public` for `cgr.dev/chainguard/...`; `org_registry`, with the identities from step 0, for `cgr.dev/$ORG/...`). The block is plain POSIX `sh`:

```sh
PLAT=linux/amd64   # the platform the workload runs on (linux/arm64 too, if used)
JDK_RE='^((openjdk|corretto|cof-corretto|zulu|liberica|adoptium-openjdk|alibabadragonwell-dragonwell)(-(fips|crac|jipher-fips))?-[0-9]+|graalvm-[0-9]+([.][0-9]+)?|mandrel-[0-9]+([.][0-9]+)?)(-[a-z0-9-]+)?$'
EMB_RE='^(ontop|ontop-fips|kafka-native|kates-native|truffleruby|geoip-api|sbt|sbt-stage0|scala-3[.]8|scala-3[.]9|scala-3[.]10|commercial-elasticsearch-9[.]4|commercial-elasticsearch-9[.]5|sonarqube|emscripten)$'   # the keys of embedded_runtimes
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
        | jq -r --arg jdk "$JDK_RE" --arg emb "$EMB_RE" '.predicate.packages[]
            | select(any(.externalRefs[]?; .referenceLocator | startswith("pkg:apk/")))   # skip upstream source entries
            | select(.name | test($jdk) or test($emb)) | "\(.name) \(.versionInfo)"' \
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

- `sbom: found, verified` plus package lines: compare them in step 3. A line for an `embedded_runtimes` package (for example ontop, kafka-native or sonarqube) means the image carries its own Java: rate it from that package's row in step 3.
- `sbom: found, verified`, `packages: N` with N above 0, and no package lines, on a Chainguard-built image: the SBOM lists no Chainguard JDK and no known embedded runtime. Confirm with 2b before rating it: an older build of a package can carry Java that `embedded_runtimes` doesn't list. Rate it from the 2b result. If `packages:` is 0 or missing, the SBOM wasn't read; use 2b.
- `sbom: found, NOT verified`: **stop** for this image (ground rule 8). It's a Chainguard-built image whose SBOM doesn't verify against Chainguard's identity. Don't mark it `UNKNOWN` and continue with 2b; report it and point the user to Support.
- `sbom: error`: cosign couldn't read the image, usually auth, network or a wrong reference. **Stop** for this image: ask the user to check access (for example `chainctl auth configure-docker`) and re-run 2a. Don't fall back to 2b, which would hit the same problem.
- `sbom: none`: there's no attestation to read. That's unusual for a Chainguard-built image (re-check that it really is one). Use 2b and say so in the report.

**2b. The image's filesystem (the user's own builds, and the fallback).** Use it for images the user built (derived images, `apk add` and apko builds, jlink or copied runtimes, mirrors rebuilt rather than copied), even if they carry an SBOM of their own, which won't list a runtime made with jlink or copied in from a build stage. Also use it when 2a prints `sbom: none`, and to confirm a Chainguard-built image whose SBOM lists no Java before rating it `NOT AFFECTED`. This doesn't run the image, and works on single- and multi-arch references. It reports four things: whether there's an apk database, any JDK packages it lists, any Java runtime directory on disk (with the version its `release` file records), and any GraalVM native executable (with the Java version compiled into it):

```sh
JDK_RE='^((openjdk|corretto|cof-corretto|zulu|liberica|adoptium-openjdk|alibabadragonwell-dragonwell)(-(fips|crac|jipher-fips))?-[0-9]+|graalvm-[0-9]+([.][0-9]+)?|mandrel-[0-9]+([.][0-9]+)?)(-[a-z0-9-]+)?$'
EMB_RE='^(ontop|ontop-fips|kafka-native|kates-native|truffleruby|geoip-api|sbt|sbt-stage0|scala-3[.]8|scala-3[.]9|scala-3[.]10|commercial-elasticsearch-9[.]4|commercial-elasticsearch-9[.]5|sonarqube|emscripten)$'   # the keys of embedded_runtimes
echo "arch: $(crane config --platform "$PLAT" "$REF" | jq -r '.architecture')"   # must match the workload's platform
FS=$(mktemp)     # needs disk space roughly twice the size of the image: the export, then its unpacked files
if ! crane export --platform "$PLAT" "$REF" - > "$FS" || [ ! -s "$FS" ]; then
  echo "export: error"   # stop for this image: an empty export would look like "no Java"
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
      awk -F: -v re="$JDK_RE" -v emb="$EMB_RE" '/^P:/{p=substr($0,3)} /^V:/{if (p ~ re || p ~ emb) print "package:", p, substr($0,3)}' "$X/$DB" | sort -u
    else
      echo "apk-db: none"
    fi
    # Java runtimes on disk, whether or not a package owns them: a directory with a `release` file and a
    # class library (lib/modules for 9+, lib/rt.jar or jre/lib/rt.jar for 8). Catches jlink output and
    # runtimes copied in from a build stage.
    find "$X" -type f -name release | while read -r r; do
      h=${r%/release}
      if [ -f "$h/lib/modules" ] || [ -f "$h/lib/rt.jar" ] || [ -f "$h/jre/lib/rt.jar" ]; then
        echo "runtime: /${h#"$X"/} $(grep -E '^(JAVA_VERSION|IMPLEMENTOR|IMPLEMENTOR_VERSION)=' "$r" | tr '\n' ' ')"
      fi
    done
    # JVM libraries outside any runtime found above (a partial copy without its `release` file)
    find "$X" -type f -name libjvm.so | while read -r j; do
      h=${j%/lib/*}; h=${h%/jre}
      [ -f "$h/release" ] || echo "jvm-file: /${j#"$X"/} $(wc -c < "$j" | tr -d ' ') bytes"
    done
    # GraalVM native executables: they embed the Java class library and record the GraalVM and Java versions
    grep -rlaF 'com.oracle.svm.core.VM=' "$X" 2>/dev/null | while read -r b; do
      echo "native: /${b#"$X"/} $(LC_ALL=C grep -aoE 'com\.oracle\.svm\.core\.VM(\.Java\.Version)?=[A-Za-z0-9 .+_-]+' "$b" | sort -u | tr '\n' ' ')"
    done
  fi
  chmod -R u+w "$X" 2>/dev/null; rm -rf "$X"
fi
rm -f "$FS"
```

This exports and unpacks the image's whole filesystem, so it's slower and needs disk space for large images. If `arch` isn't the platform the workload runs on, the image doesn't have that platform and crane exported a different one: report it and check the reference the workload actually pulls.

What the lines look like (from Chainguard images):

```
package: openjdk-27-default-jdk 27.0.1.0.3-r1
runtime: /usr/lib/jvm/java-27-openjdk IMPLEMENTOR="wolfi" IMPLEMENTOR_VERSION="openjdk-27-27.0.1.0.3-r1" JAVA_VERSION="27.0.1.0.3"
runtime: /usr/lib/jvm/java-1.8-openjdk JAVA_VERSION="1.8.0_512"
runtime: /opt/java/openjdk JAVA_VERSION="11.0.33"                              # jlink output (ontop)
native: /usr/lib/kafka-native/kafka.Kafka com.oracle.svm.core.VM.Java.Version=25.0.4.1 com.oracle.svm.core.VM=GraalVM CE 25.0.4.1.1
```

Interpreting the result:
- **`export: error` or `unpack: error`:** stop for this image and check access, as for `sbom: error`.
- **`package`, `runtime` or `native` lines:** rate each one in step 3. A JDK installed from a package shows up as both a `package` and a `runtime` line; that's one finding, not two.
- **None of these and no `jvm-file`:** `NOT AFFECTED`.
- **A `jvm-file` line:** a JVM library with no `release` file beside it. First check `not_openjdk`: StarRocks ships a 6 KB stub (`libmockjvm`) and libgcj-6 is GCJ; neither contains OpenJDK, so note it and don't rate it. A real HotSpot `libjvm.so` is many megabytes; a file under 1 MB is a stub, not a JVM. Otherwise it's usually a partial copy from a build stage: mark it `UNKNOWN`, never `NOT AFFECTED`. Find the build stage it came from (read the Dockerfile) and check that stage's base image **as it was at build time** with steps 2–3: if the stage is pinned by digest, check that digest; with a moving tag, the image's `crane config` history or the build logs may show the digest used. If you can't establish it, keep it `UNKNOWN` and recommend rebuilding with `--pull --no-cache` with the build stage pinned by a verified digest.
- Distroless Chainguard bases such as `glibc-dynamic` and `static` still have an apk database, so an empty package list alone proves nothing; the `runtime` and `native` checks are what catch a copied or jlinked runtime.
- For mirrored images, read from the mirror. If the mirror has no attestation, 2b on the mirror is the authoritative check of what you actually run.

## Step 3: Compare versions exactly (read-only)

**Never compare version strings as text** (`17.0.21.0.3` vs `17.0.21.1`, `-r10` vs `-r9`). Use apk's own comparator, which handles four- and five-part versions:

```sh
docker run --rm cgr.dev/chainguard/wolfi-base apk version -t "<installed>" "<fixed>"   # prints <, = or >
```

Rate each finding from step 2 with the first rule that applies:

1. **A package line** (from 2a or 2b), or a `runtime` line whose `IMPLEMENTOR_VERSION` has the form `<package>-<version>-r<N>` with a package name matching `sbom_jdk_regex` (split it at the last `-` before the version: `corretto-17-17.0.21.0.11-r1` is `corretto-17` `17.0.21.0.11-r1`). Map the name to its origin as `subpackages` describes, then:
   - origin in `fixed_versions`: `PATCHED` at or above the fixed version, `VULNERABLE` below it.
   - origin in `pending`: `VULNERABLE` at or below the listed build (no fixed build exists yet; step 4 makes it `WAITING ON CHAINGUARD`). A build **newer** than the listed one is `UNKNOWN`: it may carry the fix, so check the KB for that package.
   - origin in `no_fix`: `END OF LIFE`. No fixed build will ship; step 4 proposes moving to a supported Java line.
   - matches `sbom_jdk_regex` but appears in none of these: `UNKNOWN`, with "not in this skill's data" in the Action column. Check the KB, or ask Support.
2. **An `embedded_runtimes` package line:** `VULNERABLE` at or below its `vulnerable_through` build; `PATCHED` at or above its `fixed` build; any other build is `UNKNOWN` until the KB lists its fixed version. Report its `java` line and `kind` in the Java column.
3. **Any other `runtime` line** (jlink output, a runtime copied in or unpacked from a tarball): take the Java line from `JAVA_VERSION` (`1.8.0_512` is line 8, compared as `8.512`; `11.0.33` is line 11) and compare `JAVA_VERSION` with `upstream_fixed` for that line. A line not in `upstream_fixed` is `END OF LIFE`. An Azul CPU build keeps the previous update's version (`17.0.20.1.201`), so when `IMPLEMENTOR_VERSION` starts with `Zulu`, the line has a `zulu_cpu_fixed` entry and `JAVA_VERSION` is on that entry's update (the same first three parts, or for line 8 the same update number), compare with `zulu_cpu_fixed` instead. Note the result as "by runtime version" in the Action column.
4. **A `native` line** that no embedded-runtime package explains: take the line from `com.oracle.svm.core.VM.Java.Version` and compare with `upstream_fixed`. Below it is `VULNERABLE`; a line not in `upstream_fixed` is `END OF LIFE`. At or above it, the version alone doesn't show which fixes the native build contains: mark it `UNKNOWN` and check the GraalVM vendor's release notes or ask Support.

A runtime that a package installed shows up as both a package line and a `runtime` line: rate the package line and skip the duplicate.

Then, one status per image, the first that applies:

| Status | When |
|---|---|
| `UNKNOWN` | 2a or 2b couldn't be read, a `jvm-file` you couldn't trace, or any finding rated `UNKNOWN` |
| `END OF LIFE` | any finding rated `END OF LIFE` |
| `VULNERABLE` | any finding rated `VULNERABLE` |
| `PATCHED` | every finding rated `PATCHED` |
| `NOT AFFECTED` | no JDK package, no embedded-runtime package, no `runtime` or `native` line, and no `jvm-file` other than a `not_openjdk` one |

After step 4, a `VULNERABLE` Chainguard-built image whose fix isn't in the user's registry yet becomes `WAITING ON CHAINGUARD`.

**Dockerfiles with no built image to inspect:** rate them from their pins and base images. An `apk add` pin below the fixed version is `VULNERABLE`. Otherwise check each `FROM` image with steps 2–3, including the build stages a runtime is jlinked or copied from, and check the image the Dockerfile produces once it's built.

**apko configs and lockfiles:** the lockfile decides the version, but **only if the build passes `apko build --lockfile …`**; apko doesn't pick it up on its own, so check the Makefile or CI. Read the locked version per architecture:

```sh
jq -r --arg jdk "$JDK_RE" '.contents.packages[] | select(.name | test($jdk)) | "\(.name) \(.version) \(.architecture)"' apko.lock.json
```

Any entry below the fixed version is `VULNERABLE` (note "by lock"). Without a lockfile in use, an exact pin (`openjdk-21-default-jdk=21.0.13.0.3-r1`) below the fixed version is `VULNERABLE` (note "by pin"); a fuzzy pin (`~`) or an unpinned package resolves at build time, so check the built image.

Show the user the inventory table now (see Report format) before proposing any changes.

## Step 4: Plan the fix for each vulnerable reference (propose, then wait for approval)

For **images Chainguard builds** (catalog, Custom Assembly and custom images), first check whether a patched build exists **in the user's registry**: resolve the tag's current digest and repeat steps 2–3 on it. If it's still vulnerable, go to step 6 for that image. To list newer builds of a tag in an org registry: `chainctl images history IMAGE:TAG --parent $ORG`. For **images the user builds**, the fix is a rebuild (rows below), not Support.

To tell a mirror copy from the user's own build: a mirror copy has the same digest as the image in `cgr.dev/$ORG` (compare `crane digest` on both); the user's own build has a different digest, and its `crane config` history shows their build steps.

| How it's referenced | Proposed change |
|---|---|
| By tag (`:21`), and the tag now points to a patched digest | Propose pinning the reference to the digest you verified in steps 2–3 and 5 (`IMAGE:TAG@sha256:…`), then roll out (step 7). A restart alone can reuse a cached image (`imagePullPolicy: IfNotPresent`), and the tag can move after you verified it. |
| By digest (`@sha256:…`) | Replace it with the patched digest you verified in steps 2–3 (and step 5). A pinned digest never picks up a fix on its own. Propose the exact diff. |
| Via a mirror | Propose copying the **verified digest**, not the tag (which can move): `cosign copy cgr.dev/$ORG/IMAGE@sha256:<verified> <mirror>/IMAGE:TAG`. This copies signatures and attestations too. Then compare digests on both sides. |
| Via a pull-through cache (Artifactory remote repo, Harbor proxy cache) | These can't receive a push. Propose refreshing or expiring the cached tag, or referencing the verified digest, which the cache will fetch. |
| Derived image (`FROM cgr.dev/...`) | If the `FROM` line is pinned by digest, first propose bumping it to a verified, patched digest (show the diff): rebuilding a pinned base rebuilds the same vulnerable image. Then rebuild with `--pull --no-cache`, push, and update references to the new image. Verify the rebuilt image with steps 2–3: it has no Chainguard attestation, so step 2b applies. |
| Runtime built with jlink, or a JDK or JRE copied from a build stage | The runtime keeps the Java version it was built from; updating the final stage's base image doesn't change it. Propose bumping the **build stage** that provides the JDK (its `FROM`, or its `apk add` pins, including the `-jmods` package jlink reads) to a patched version, then rebuild with `--pull --no-cache`. Verify with step 2b: the `runtime` line must show a fixed `JAVA_VERSION` (or `IMPLEMENTOR_VERSION`). |
| Own GraalVM native executable | Rebuild it with a GraalVM release that includes this update, then re-check its `native` line. Until the vendor's release notes confirm the fixes, keep it `UNKNOWN` (step 3). |
| Image with an embedded runtime (an `embedded_runtimes` package) | These are fixed by a new build of the image's own package, not by an OpenJDK update. Several ship a native executable built by the upstream project (sbt, scala-cli, Elasticsearch's launcher in commercial-elasticsearch and sonarqube, emscripten's closure compiler), so the fix depends on that project. When the KB lists a fixed build, pull it and handle the reference as in the rows above. Until then, report `WAITING ON CHAINGUARD` (step 6). |
| Dockerfile with `apk add` of a JDK package | Raise or remove old pins and fail closed, for example `apk add --no-cache 'openjdk-21-default-jdk>=21.0.13.1-r0'`. Upgrade every JDK subpackage it installs too (`-jre`, `-jmods`, `-default-jvm`). Rebuild with `--pull --no-cache`, then verify the result with steps 2b–3. If a policy blocks the new versions, tell the user to contact their org admin or Support; don't change policy yourself. |
| apko config or lockfile | Raise or remove the YAML pin (or use `openjdk-21-default-jdk>=21.0.13.1-r0`), then regenerate the lockfile with `apko lock`. That moves **every** package to its newest version, so show the user the whole lockfile diff for approval, not just the JDK lines. Rebuild, then verify with steps 2b–3. |
| Custom Assembly image | These rebuild automatically unless the configuration pins JDK package versions. If your chainctl has it, read the pins with `chainctl images overlays list --parent "$ORG" -o json` (packages under `.overlays[].config.contents.packages`, repos under `.bindings[]`; check the output's shape before relying on it). Otherwise ask the user to check the configuration in the Chainguard Console. Propose raising or removing the pins. Then verify the rebuilt image with steps 2–3. |
| Vendor or variant JDK still in `pending` (Temurin 8 and 11, Liberica, Dragonwell, OpenJ9, CRaC, GraalVM, Mandrel) | No fixed build exists yet: each waits for its own upstream release. Report `WAITING ON CHAINGUARD` (step 6). Don't propose switching to another vendor's JDK yourself; that's the user's decision. |
| `END OF LIFE` (a `no_fix` package, or a runtime on a Java line not in `upstream_fixed`) | No fix will ship. Propose moving to a supported line: the nearest LTS (8, 11, 17, 21 or 25) or 27, as the application allows. Don't change anything automatically. |

Group the plan by repository or cluster. For each item, show the file and line or the workload, the current and target references, and the exact command or diff. Ask for approval per item or per group.

## Step 5: Verify signatures before anything new is deployed (read-only)

Verify every target digest with the matching `signature_verify` command from the data block, substituting `IMAGE@DIGEST`. Use `public` for `cgr.dev/chainguard/...` and `org_registry` for `cgr.dev/$ORG/...`. Images the user builds themselves aren't signed by Chainguard; verify them with the user's own signing policy, if any. For a mirror, verify the `cgr.dev` digest you copied from, or the mirror copy if it was made with `cosign copy`.

For the org registry, use the org's two signing identities from step 0.

**Check both values before running cosign.** Each must be a non-empty identity of the form `<hex>/<hex>`, not empty and not `null`. cosign matches `--certificate-identity-regexp` anywhere in the certificate subject, so an empty alternative in `(${IMAGE_SYNCER}|${CUSTOM_IMAGE_BUILDER})` would accept a signature from *any* `issuer.enforce.dev` identity. If one value is missing, drop it from the group (for example `(${IMAGE_SYNCER})`). If both are missing, stop: report it, and point the user to Support.

If verification fails for an image, **stop**: don't deploy that image; report it and point the user to Support. Never retry with a looser identity or issuer.

## Step 6: If the fix isn't in the user's registry yet

Patched images reach customer registries automatically after Chainguard publishes them; this can take additional time.

- Report the image, tag and digest as `WAITING ON CHAINGUARD`, and help the user open a Support request at https://support.chainguard.dev, including the image, tag, digest and the Java package or runtime version from step 2.
- Don't switch the user to public images, another registry or another vendor's JDK as a workaround; that's a Support decision.
- If they can't update yet, point them to Oracle's advisory (`disclosure`) for any mitigations per CVE. Say clearly that these reduce exposure but don't make an installation safe, and don't change JVM options without approval (ground rule 2).

## Step 7: Apply approved changes and roll out

- Make only the approved edits. Commit on a branch and open a PR if the repo uses one.
- Roll out the way the user normally does (GitOps sync, `helm upgrade`, `kubectl apply`), with the references pinned to verified digests. Don't rely on `kubectl rollout restart` for tag references: nodes that cached the tag keep running the old image.
- Sync mirrors before redeploying anything that pulls from them.

## Step 8: Re-verify and report

1. Re-run the step 1 `kubectl` query and confirm every affected workload now runs a `PATCHED` digest (repeat steps 2–3 on the running `imageID`s, not just the manifests).
2. Scanners: Chainguard's feeds list the fixes for Chainguard's JDK packages. If a scanner still flags a patched image, refresh its database (for grype: `grype db update`) and confirm it reads a feed in `scanner_feeds`. Scanners match on SBOM packages, so they can't see an embedded runtime, a jlinked or copied runtime, or a native executable: steps 2–3 are the confirmation for those, and a clean scan proves nothing about them.
3. Produce the final report.

### Report format

```
Chainguard Java4Shell (CVE-2026-114938) and the November 2026 Java SE update — remediation report (<date, UTC>)

| Where used (file:line / ns/workload) | Image reference | Digest | Java found (package / runtime / native) | Status | Action taken / proposed |
|---|---|---|---|---|---|
| k8s prod/api-7f9 | cgr.dev/acme/jre:21 | sha256:… | openjdk-21-jre 21.0.13.0.3-r1 | VULNERABLE → PATCHED | pinned verified digest (approved 14:02) |
| svc/Dockerfile:12 | registry.corp/app:1.4 | sha256:… | runtime /opt/app/jre JAVA_VERSION="17.0.21.0.3" | VULNERABLE | bump build stage `jdk` to a patched digest (proposed); by runtime version |
| k8s kg/ontop-0 | cgr.dev/acme/ontop:latest | sha256:… | ontop 5.5.0-r34 (jlink, Java 11) | WAITING ON CHAINGUARD | embedded runtime; fixed build 5.5.0-r35 not in the registry yet |

Summary: N references checked · patched · not affected · vulnerable · end of life · unknown · waiting on Chainguard
Open items: (each with the next step and owner)
```

Statuses (from step 3, plus step 4's `WAITING ON CHAINGUARD`): `PATCHED`, `NOT AFFECTED`, `VULNERABLE`, `END OF LIFE`, `UNKNOWN`, `WAITING ON CHAINGUARD`. Put the reason in the Action column (for example "pin in svc/Dockerfile:4", "by runtime version" or "runtime copied from build stage `build`"), not in the status.

## Troubleshooting (map the user's symptom to the cause)

| Symptom | Likely cause → what to do |
|---|---|
| Scanner still reports the CVEs on a patched image | Stale scanner DB or wrong feed → refresh, confirm `scanner_feeds`; re-check the version with steps 2–3 |
| Scanner reports nothing for an image that runs Java | Embedded, jlinked or copied runtime, which the SBOM doesn't list → step 2b |
| `java -version` shows `17.0.21.1`, not `17.0.22` | Expected: Oracle numbered this release with four parts. Compare with apk's comparator (step 3) |
| Corretto shows a five-part version such as `17.0.21.1.2` | Expected: Corretto adds its own build number. It has its own row in `fixed_versions` |
| The image's SBOM doesn't list OpenJDK, but the image runs Java | An embedded runtime (ontop, kafka-native) or one you built → steps 2a and 2b |
| A jlinked runtime is still old after updating the base image | The runtime keeps the version of the JDK it was linked from → bump the build stage (step 4) |
| Tag still resolves to an old version | Registry not synced (step 6) or mirror not synced (step 4) |
| Workload still runs the old build | Digest pin, a cached tag (`imagePullPolicy: IfNotPresent`), or pods not restarted (steps 4, 7) |
| Custom Assembly image still old | A pinned JDK version in its configuration (step 4) |
| Own build still installs an old JDK | Cached layer or an old `apk add` pin → `--pull --no-cache`, raise the pin |

## Escalation

https://support.chainguard.dev. Include the image, tag and digest, the Java package or runtime version from step 2, and this report. Status updates: https://status.chainguard.dev.
