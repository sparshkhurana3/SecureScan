#!/bin/sh
# Spike S7: build securescan/spotbugs-fsb from scanners/spotbugs/Dockerfile with verified checksums.
#
#   export SPOTBUGS_SHA256=<sha256 of spotbugs-4.10.4.zip>
#   export FSB_SHA256=<sha256 of findsecbugs-plugin-1.14.0.jar>
#   sh spikes/s7/build_spotbugs.sh
#
# How to obtain the two values from the publishers: scanners/spotbugs/README.md. The build fails when either is empty.
# Optional: SPOTBUGS_VERSION (default 4.10.4), FSB_VERSION (default 1.14.0), BASE_IMAGE (default eclipse-temurin:21-jre; pin by digest for releases).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
: "${SPOTBUGS_SHA256:?set SPOTBUGS_SHA256 (see scanners/spotbugs/README.md)}"
: "${FSB_SHA256:?set FSB_SHA256 (see scanners/spotbugs/README.md)}"
SB=${SPOTBUGS_VERSION:-4.10.4}
FSB=${FSB_VERSION:-1.14.0}
TAG="securescan/spotbugs-fsb:$SB-$FSB"
docker build -t "$TAG" \
  --build-arg "SPOTBUGS_VERSION=$SB" --build-arg "FSB_VERSION=$FSB" \
  --build-arg "SPOTBUGS_SHA256=$SPOTBUGS_SHA256" --build-arg "FSB_SHA256=$FSB_SHA256" \
  ${BASE_IMAGE:+--build-arg "BASE_IMAGE=$BASE_IMAGE"} \
  "$ROOT/scanners/spotbugs"
echo "built $TAG"
docker run --rm "$TAG" -version
echo "image id: $(docker image inspect -f '{{.Id}}' "$TAG")"
echo "plugin jar and launcher:"
docker run --rm --entrypoint sh "$TAG" -c 'ls -l /opt/spotbugs/bin/spotbugs /opt/findsecbugs/findsecbugs-plugin.jar; id' || true
