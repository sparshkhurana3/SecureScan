# SpotBugs + Find Security Bugs, built from pinned, checksum-verified releases.
# Neither project publishes an official image (design: "Scanner catalogue"), so SecureScan builds this one.
#
# Build (see README.md for how to obtain the checksums; the build FAILS when they are empty):
#   docker build -t securescan/spotbugs-fsb:4.10.4-1.14.0 \
#     --build-arg SPOTBUGS_SHA256=<sha256 of spotbugs-4.10.4.zip> \
#     --build-arg FSB_SHA256=<sha256 of findsecbugs-plugin-1.14.0.jar> \
#     scanners/spotbugs
# Or use spikes/s7/build_spotbugs.sh, which reads SPOTBUGS_SHA256 and FSB_SHA256 from the environment.
#
# Run (the M8 catalogue entry; a read-only rootfs works because SpotBugs writes only to /out and /tmp):
#   docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000 \
#     --tmpfs /tmp:rw,size=512m,uid=1000,gid=1000 -v <classes>:/src:ro -v <out>:/out:rw securescan/spotbugs-fsb:4.10.4-1.14.0 \
#     -textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -xml:withMessages=/out/spotbugs.xml /src/<app>.jar
#
# Licences: SpotBugs LGPL-2.1, Find Security Bugs LGPL-3.0, Eclipse Temurin GPL-2.0 with Classpath Exception (base image only).

# The base image is pinned by digest in deploy/images.lock.yaml at release time; the tag below is for development builds.
ARG BASE_IMAGE=eclipse-temurin:21-jre
ARG SPOTBUGS_VERSION=4.10.4
ARG FSB_VERSION=1.14.0

# ---- stage 1: download and verify (needs network; not part of the final image) ----
FROM ${BASE_IMAGE} AS fetch
ARG SPOTBUGS_VERSION
ARG FSB_VERSION
# TO BE FILLED from the official release pages (see README.md). Empty on purpose: an empty value fails the build.
ARG SPOTBUGS_SHA256=
ARG FSB_SHA256=
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eu; \
    if [ -z "${SPOTBUGS_SHA256}" ] || [ -z "${FSB_SHA256}" ]; then \
      echo "SPOTBUGS_SHA256 and FSB_SHA256 build arguments are required (see scanners/spotbugs/README.md)" >&2; exit 1; \
    fi; \
    curl -fsSL --retry 3 -o "spotbugs-${SPOTBUGS_VERSION}.zip" \
      "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.zip"; \
    curl -fsSL --retry 3 -o "findsecbugs-plugin-${FSB_VERSION}.jar" \
      "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FSB_VERSION}/findsecbugs-plugin-${FSB_VERSION}.jar"; \
    printf '%s  %s\n%s  %s\n' \
      "${SPOTBUGS_SHA256}" "spotbugs-${SPOTBUGS_VERSION}.zip" \
      "${FSB_SHA256}" "findsecbugs-plugin-${FSB_VERSION}.jar" > SHA256SUMS; \
    sha256sum -c SHA256SUMS; \
    unzip -q "spotbugs-${SPOTBUGS_VERSION}.zip" -d /opt; \
    mv "/opt/spotbugs-${SPOTBUGS_VERSION}" /opt/spotbugs; \
    mkdir -p /opt/findsecbugs; \
    cp "findsecbugs-plugin-${FSB_VERSION}.jar" /opt/findsecbugs/findsecbugs-plugin.jar; \
    chmod -R a+rX /opt/spotbugs /opt/findsecbugs; \
    chmod a+x /opt/spotbugs/bin/spotbugs

# ---- stage 2: the scanner image ----
FROM ${BASE_IMAGE}
ARG SPOTBUGS_VERSION
ARG FSB_VERSION
LABEL org.opencontainers.image.title="securescan-spotbugs-fsb" \
      org.opencontainers.image.description="SpotBugs ${SPOTBUGS_VERSION} with Find Security Bugs ${FSB_VERSION}" \
      org.opencontainers.image.licenses="LGPL-2.1-only AND LGPL-3.0-only" \
      securescan.spotbugs.version="${SPOTBUGS_VERSION}" \
      securescan.findsecbugs.version="${FSB_VERSION}"
COPY --from=fetch /opt/spotbugs /opt/spotbugs
COPY --from=fetch /opt/findsecbugs /opt/findsecbugs
# uid 1000 is what the worker and the other scanner images use. Ubuntu-based Temurin images may already define a user
# with uid 1000 ("ubuntu"); only create one when it does not exist. The numeric USER works either way.
RUN id -u 1000 >/dev/null 2>&1 || (groupadd -g 1000 scanner && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin scanner)
USER 1000:1000
WORKDIR /src
# The launcher script's default heap is 768 MB; raise it per job with the launcher's own `-maxHeap <MB>` option.
ENTRYPOINT ["/opt/spotbugs/bin/spotbugs"]
CMD ["-version"]
