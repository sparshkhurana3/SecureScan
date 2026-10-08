#!/bin/sh
# Spike S5: WeasyPrint 70 in the slim backend image (deploy/backend/Dockerfile).
#
#   sh spikes/s5-weasyprint/run.sh
#
# Prerequisites: Docker, network (the image build installs apt packages and Python wheels) and backend/uv.lock
# (created by `cd backend && uv lock`; the Dockerfile copies it). Run from anywhere; paths are resolved from this file.
#
# What it does: builds the image, prints the apt packages it contains, renders the sample PDF twice (normal container;
# then hardened with --read-only and tmpfs only), copies the stamped PDF to docs/spikes/weasyprint-sample.pdf and prints
# the package list for the findings file. Exit code 1 on the first failure.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
IMAGE=${S5_IMAGE_TAG:-securescan-backend:spike-s5}
OUT="$HERE/.data/out"

if [ ! -f "$ROOT/backend/uv.lock" ]; then
  echo "backend/uv.lock is missing: run 'cd backend && uv lock' first (M0 step 1)." >&2
  exit 1
fi
rm -rf "$OUT"; mkdir -p "$OUT"; chmod 0777 "$OUT"

echo "== docker build ($IMAGE)"
docker build -f "$ROOT/deploy/backend/Dockerfile" -t "$IMAGE" "$ROOT"

echo "== apt packages in the runtime image (manually installed, then the libraries WeasyPrint loads)"
docker run --rm --entrypoint sh "$IMAGE" -c \
  'apt-mark showmanual | sort; echo ---; dpkg-query -W -f="\${Package} \${Version}\n" | grep -E "pango|harfbuzz|fontconfig|fonts-liberation|cairo|glib|freetype|libpng|fribidi" | sort; echo ---; id; echo HOME=$HOME'

run_render() {
  mode=$1; shift
  echo "== render ($mode)"
  docker run --rm --entrypoint /app/.venv/bin/python "$@" \
    -v "$HERE:/spike:ro" \
    -v "$ROOT/frontend/src/brand/wordmark.svg:/brand/wordmark.svg:ro" \
    -v "$OUT:/out" \
    "$IMAGE" /spike/render.py --out /out
}

run_render "plain container (as the api and worker containers run today)"
rc=0
run_render "hardened: --read-only, tmpfs /tmp and /home/app/.cache (fontconfig cache), no capabilities" \
  --read-only --tmpfs /tmp:rw,size=256m,uid=1000,gid=1000 --tmpfs /home/app/.cache:rw,size=64m,uid=1000,gid=1000 \
  --cap-drop ALL --security-opt no-new-privileges || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "NOTE: the hardened render failed (exit $rc). If it is a fontconfig or cache write error, record the writable path that is needed." >&2
fi

cp "$OUT/sample-watermarked.pdf" "$ROOT/docs/spikes/weasyprint-sample.pdf"
ls -l "$ROOT/docs/spikes/weasyprint-sample.pdf"
echo "OK: sample PDF checked in at docs/spikes/weasyprint-sample.pdf (commit it); the apt list is printed above."
