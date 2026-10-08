#!/bin/sh
# Spike S2 driver: socket-proxy allowlist discovery and enforcement.
#
#   sh spikes/s2/run.sh discover   # proxy allows everything + DEBUG; derive_paths.py records the SDK's requests and
#                                  # writes spikes/s2/.data/enforce.env (candidate allowlist)
#   sh spikes/s2/run.sh enforce    # proxy started with enforce.env; test_allowlist.py + the intruder check
#   sh spikes/s2/run.sh all        # discover, then enforce
#   sh spikes/s2/run.sh logs       # proxy log of the last pass
#   sh spikes/s2/run.sh down       # remove containers, networks, and the volume if this script created it
#
# Needs: Docker Engine on this host (rootful, /var/run/docker.sock), network access to pull images and to pip install
# `docker` and `httpx` into the client container. Environment (optional): S2_IMAGE (default busybox:1.37),
# S2_SONAR_NAME (default sonarqube), SOCKET_PROXY_VERSION (default 1.13.1), S2_VOLUME (default securescan_data).
#
# Output is plain text; paste the relevant parts into docs/spikes/s2-socket-proxy.md. Files: spikes/s2/.data/.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
mkdir -p .data

S2_IMAGE=${S2_IMAGE:-busybox:1.37}
S2_VOLUME=${S2_VOLUME:-securescan_data}
S2_SONAR_NAME=${S2_SONAR_NAME:-sonarqube}
S2_WORKSPACE=${S2_WORKSPACE:-s2job}
NET_A=${S2_NET_A:-s2-net-a}
NET_B=${S2_NET_B:-s2-net-b}
export S2_IMAGE S2_SONAR_NAME
DOCKER_GID=$(stat -c %g /var/run/docker.sock)
HOST_UID=$(id -u)
HOST_GID=$(id -g)
export DOCKER_GID HOST_UID HOST_GID

compose() { docker compose -f "$HERE/docker-compose.yml" "$@"; }

prepare() {
  echo "== prepare: images, networks, volume, workspace directories"
  if docker inspect "$S2_SONAR_NAME" >/dev/null 2>&1; then
    echo "A container named '$S2_SONAR_NAME' already exists on this host. The spike creates and removes a container with"
    echo "that name. Stop the real one, or set S2_SONAR_NAME to another name (then the regexes use that name)." >&2
    exit 1
  fi
  for image in "$S2_IMAGE" "python:3.14-slim-trixie" "wollomatic/socket-proxy:${SOCKET_PROXY_VERSION:-1.13.1}"; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
  done
  for net in "$NET_A" "$NET_B"; do
    docker network inspect "$net" >/dev/null 2>&1 || docker network create "$net" >/dev/null
  done
  if ! docker volume inspect "$S2_VOLUME" >/dev/null 2>&1; then
    docker volume create "$S2_VOLUME" >/dev/null
    : > .data/created-volume
    echo "created volume $S2_VOLUME (will be removed by 'down')"
  fi
  # The daemon creates missing bind sources as root; create them first, world-writable like the M3 workspaces.
  docker run --rm -v "$S2_VOLUME:/d" "$S2_IMAGE" sh -c \
    "mkdir -p /d/workspaces/$S2_WORKSPACE/src /d/workspaces/$S2_WORKSPACE/out && echo hello > /d/workspaces/$S2_WORKSPACE/src/hello.txt && chmod -R 0777 /d/workspaces/$S2_WORKSPACE"
}

wait_proxy() {
  i=0
  until compose exec -T client python -c "import socket; socket.create_connection(('socket-proxy', 2375), 3)" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then
      echo "socket-proxy did not start; its log:" >&2
      compose logs --no-color socket-proxy >&2 || true
      exit 1
    fi
    sleep 1
  done
}

install_deps() {
  echo "== client: pip install docker httpx"
  compose exec -T client python -m pip install --quiet --user docker httpx
}

start() {
  env_file=$1
  S2_ENV_FILE=$env_file compose up -d --force-recreate socket-proxy client intruder
  wait_proxy
}

discover() {
  prepare
  echo "== DISCOVER: proxy allows everything (spikes/s2/discover.env), DEBUG log"
  start ./discover.env
  install_deps
  rc=0
  compose exec -T client python /spike/derive_paths.py || rc=$?
  compose logs --no-color socket-proxy > .data/proxy-debug.log 2>&1 || true
  echo "== proxy DEBUG log saved to spikes/s2/.data/proxy-debug.log ($(wc -l < .data/proxy-debug.log) lines); first lines:"
  head -n 40 .data/proxy-debug.log || true
  if [ "$rc" -ne 0 ]; then echo "derive_paths.py failed (exit $rc)" >&2; exit "$rc"; fi
  echo "== candidate allowlist: spikes/s2/.data/enforce.env"
  cat .data/enforce.env
}

enforce() {
  if [ ! -f .data/enforce.env ]; then echo "run 'discover' first (it writes .data/enforce.env)" >&2; exit 1; fi
  prepare
  echo "== ENFORCE: proxy started with spikes/s2/.data/enforce.env"
  start ./.data/enforce.env
  install_deps
  echo "== proxy start-up log (it prints the allowlist it parsed)"
  compose logs --no-color socket-proxy | head -n 30
  rc=0
  compose exec -T client python /spike/test_allowlist.py || rc=$?
  echo "== intruder (not in -allowfrom) must be refused"
  irc=0
  compose exec -T intruder python /spike/intruder_check.py || irc=$?
  compose logs --no-color socket-proxy > .data/proxy-enforce.log 2>&1 || true
  echo "== exit codes: test_allowlist.py=$rc intruder_check.py=$irc"
  if [ "$rc" -ne 0 ] || [ "$irc" -ne 0 ]; then exit 1; fi
}

down() {
  compose down --volumes --remove-orphans || true
  docker rm -f "$S2_SONAR_NAME" >/dev/null 2>&1 || true
  for net in "$NET_A" "$NET_B"; do docker network rm "$net" >/dev/null 2>&1 || true; done
  if [ -f .data/created-volume ]; then
    docker volume rm "$S2_VOLUME" >/dev/null 2>&1 || true
    rm -f .data/created-volume
  fi
}

case "${1:-}" in
  discover) discover ;;
  enforce) enforce ;;
  all) discover; enforce ;;
  logs) compose logs --no-color socket-proxy ;;
  down) down ;;
  *) echo "usage: sh spikes/s2/run.sh discover|enforce|all|logs|down" >&2; exit 2 ;;
esac
