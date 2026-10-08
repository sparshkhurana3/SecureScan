#!/bin/sh
# Spike S7: everything that needs the network, so that the scanner runs themselves can use `--network none`.
#
#   sh spikes/s7/prefetch.sh images      # docker pull of every pinned scanner image (not SpotBugs: it is built locally)
#   sh spikes/s7/prefetch.sh grype       # fill the Grype DB volume (s7_grype_db) with `grype db update`
#   sh spikes/s7/prefetch.sh nuclei      # fill the Nuclei templates volume (s7_nuclei_templates)
#   sh spikes/s7/prefetch.sh semgrep     # clone semgrep-rules and keep the language directories under spikes/s7/.data/content
#   sh spikes/s7/prefetch.sh all         # all of the above
#
# Dependency-Check's NVD update is a separate script because it runs for 20+ minutes: spikes/s7/odc_update.sh.
# Image references come from deploy/images.env (python scripts/dev.py pin-images) or the tags in deploy/images.lock.yaml.
# Semgrep's rules are under the Semgrep Rules License v1.0: internal use only; nothing here is committed (.data is git-ignored).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DATA="$HERE/.data"
CONTENT="$DATA/content"
mkdir -p "$DATA" "$CONTENT"
if [ -f "$ROOT/deploy/images.env" ]; then set -a; . "$ROOT/deploy/images.env"; set +a; fi
: "${IMG_SEMGREP:=semgrep/semgrep:1.179.0-nonroot}"
: "${IMG_GITLEAKS:=ghcr.io/gitleaks/gitleaks:v8.30.1}"
: "${IMG_SYFT:=anchore/syft:v1.54.0}"
: "${IMG_GRYPE:=anchore/grype:v0.120.0}"
: "${IMG_DEPENDENCY_CHECK:=owasp/dependency-check:13.0.0}"
: "${IMG_ZAP:=ghcr.io/zaproxy/zaproxy:stable}"
: "${IMG_NUCLEI:=projectdiscovery/nuclei:v3.11.1}"
SEMGREP_RULES_REF=${S7_SEMGREP_RULES_REF:-}   # empty = the default branch head; set a commit to pin
JUICE=${S7_JUICESHOP_IMAGE:-bkimminich/juice-shop}
UTIL=${S7_UTIL_IMAGE:-busybox:1.37}

images() {
  for ref in "$IMG_SEMGREP" "$IMG_GITLEAKS" "$IMG_SYFT" "$IMG_GRYPE" "$IMG_DEPENDENCY_CHECK" "$IMG_ZAP" "$IMG_NUCLEI" \
             "eclipse-temurin:21-jre" "$JUICE" "$UTIL"; do
    echo "== docker pull $ref"
    docker pull "$ref"
  done
  echo "== digests of what was pulled (record them in docs/spikes/s7-scanner-contract.md)"
  for ref in "$IMG_SEMGREP" "$IMG_GITLEAKS" "$IMG_SYFT" "$IMG_GRYPE" "$IMG_DEPENDENCY_CHECK" "$IMG_ZAP" "$IMG_NUCLEI"; do
    docker image inspect -f '{{index .RepoDigests 0}}' "$ref" 2>/dev/null || echo "no digest for $ref"
  done
}

grype() {
  echo "== grype db update into volume s7_grype_db (network on, this step only)"
  docker volume create s7_grype_db >/dev/null
  docker run --rm -v s7_grype_db:/content/grype-db -e GRYPE_DB_CACHE_DIR=/content/grype-db \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false "$IMG_GRYPE" db update
  docker run --rm -v s7_grype_db:/content/grype-db -e GRYPE_DB_CACHE_DIR=/content/grype-db \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false "$IMG_GRYPE" db status || true
}

nuclei() {
  echo "== nuclei templates into volume s7_nuclei_templates (network on, this step only)"
  docker volume create s7_nuclei_templates >/dev/null
  docker volume create s7_nuclei_config >/dev/null
  docker run --rm -v s7_nuclei_templates:/content/nuclei-templates -v s7_nuclei_config:/cfg \
    -e NUCLEI_CONFIG_DIR=/cfg "$IMG_NUCLEI" -ut -ud /content/nuclei-templates
}

semgrep() {
  echo "== semgrep-rules (internal use only)"
  rm -rf "$CONTENT/semgrep-rules-src" "$CONTENT/semgrep-rules"
  git clone --quiet https://github.com/semgrep/semgrep-rules "$CONTENT/semgrep-rules-src"
  if [ -n "$SEMGREP_RULES_REF" ]; then git -C "$CONTENT/semgrep-rules-src" checkout --quiet "$SEMGREP_RULES_REF"; fi
  mkdir -p "$CONTENT/semgrep-rules"
  for d in java javascript typescript python csharp generic html yaml; do
    if [ -d "$CONTENT/semgrep-rules-src/$d" ]; then cp -R "$CONTENT/semgrep-rules-src/$d" "$CONTENT/semgrep-rules/$d"; fi
  done
  git -C "$CONTENT/semgrep-rules-src" rev-parse HEAD > "$CONTENT/semgrep-rules.commit"
  chmod -R a+rX "$CONTENT/semgrep-rules"
  echo "rules directories: $(ls "$CONTENT/semgrep-rules" | tr '\n' ' ')  commit $(cat "$CONTENT/semgrep-rules.commit")"
  echo "M8's updater must also drop rules whose metadata.license is not the Semgrep Rules License v1.0 (and the AGPL trailofbits.* rules);"
  echo "this spike copies whole language directories and does not filter."
}

case "${1:-}" in
  images) images ;;
  grype) grype ;;
  nuclei) nuclei ;;
  semgrep) semgrep ;;
  all) images; grype; nuclei; semgrep ;;
  *) echo "usage: sh spikes/s7/prefetch.sh images|grype|nuclei|semgrep|all" >&2; exit 2 ;;
esac
