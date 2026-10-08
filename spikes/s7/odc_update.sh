#!/bin/sh
# Spike S7: start the OWASP Dependency-Check NVD update EARLY. It takes 20 minutes or more, so run it first, in the background,
# and do the other spikes meanwhile. run_all.sh refuses to run Dependency-Check until this has finished successfully.
#
#   NVD_API_KEY=<key> sh spikes/s7/odc_update.sh          # or: NVD_API_KEY_FILE=/path/to/file
#   sh spikes/s7/odc_update.sh status                       # progress and result
#   sh spikes/s7/odc_update.sh stop                         # abort
#
# The key (free, from https://nvd.nist.gov/developers/request-an-api-key) goes into spikes/s7/.data/odc-config/odc.properties
# (git-ignored) as `nvd.api.key=<key>` and is mounted read-only at /config: never on a command line. Without a key the update
# still tries but is very slow and usually hits NVD rate limits.
# The property name nvd.api.key is the plan's expectation; the log in .data/odc-update.log shows whether Dependency-Check
# picked the key up (look for lines about the API key); record the answer in docs/spikes/s7-scanner-contract.md.
# Data lands in the named volume s7_odc_data (the same layout as the future `odc_data` volume).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DATA="$HERE/.data"
CONF="$DATA/odc-config"
LOG="$DATA/odc-update.log"
DONE="$DATA/odc-update.done"
NAME=s7-odc-update
mkdir -p "$DATA" "$CONF"
if [ -f "$ROOT/deploy/images.env" ]; then set -a; . "$ROOT/deploy/images.env"; set +a; fi
: "${IMG_DEPENDENCY_CHECK:=owasp/dependency-check:13.0.0}"

case "${1:-start}" in
  status)
    if docker inspect "$NAME" >/dev/null 2>&1; then echo "running; last log lines:"; tail -n 8 "$LOG" 2>/dev/null || true; else echo "not running"; fi
    if [ -f "$DONE" ]; then echo "finished with exit code $(cat "$DONE")"; fi
    exit 0 ;;
  stop) docker rm -f "$NAME" >/dev/null 2>&1 || true; echo stopped; exit 0 ;;
  start) : ;;
  *) echo "usage: sh spikes/s7/odc_update.sh [start|status|stop]" >&2; exit 2 ;;
esac

KEY=${NVD_API_KEY:-}
if [ -z "$KEY" ] && [ -n "${NVD_API_KEY_FILE:-}" ]; then KEY=$(tr -d '\r\n' < "$NVD_API_KEY_FILE"); fi
if [ -n "$KEY" ]; then
  printf 'nvd.api.key=%s\n' "$KEY" > "$CONF/odc.properties"
  echo "NVD key written to $CONF/odc.properties"
else
  : > "$CONF/odc.properties"
  echo "WARNING: no NVD_API_KEY: the update will be slow and may be rate limited" >&2
fi
# The container user (uid 1000) must be able to read it; the directory is git-ignored and below your home.
chmod 0755 "$CONF"
chmod 0644 "$CONF/odc.properties"

docker volume create s7_odc_data >/dev/null
rm -f "$DONE"
docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "starting the update in the background; log: $LOG"
nohup sh -c "docker run --name $NAME --rm -v s7_odc_data:/usr/share/dependency-check/data -v '$CONF:/config:ro' '$IMG_DEPENDENCY_CHECK' --updateonly --data /usr/share/dependency-check/data --propertyfile /config/odc.properties > '$LOG' 2>&1; echo \$? > '$DONE'" >/dev/null 2>&1 &
echo "started. Check with: sh spikes/s7/odc_update.sh status   (finished = $DONE contains 0)"
