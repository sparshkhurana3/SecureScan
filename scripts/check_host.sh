#!/usr/bin/env bash
# Checks that this machine can run SecureScan: cgroup v2, Docker Engine and Compose versions,
# time sync, memory and disk. Read-only: it changes nothing. Run it on the Linux machine before the first start
# and after every OS or Docker upgrade:
#
#   bash scripts/check_host.sh              # exit 0: nothing failed (warnings are listed), exit 1: something failed
#   bash scripts/check_host.sh --network    # also test outbound HTTPS to the hosts of docs/install.md (direct, not through a proxy)
#
# The worker repeats the checks it can see from inside its container when it starts
# (backend/securescan/runner/host_check.py; SECURESCAN_HOST_CHECK=enforce refuses to start scans if one fails).
#
# Requirements this script checks (docs/implementation-plan.md section 2.4):
#   cgroup v2 with the memory, pids and cpu controllers; Docker Engine 29 or later (25 is the hard minimum);
#   Docker Compose 2.24 or later; 4 vCPU / 8 GB minimum (docs/decisions.md, 2026-10-21); 100 GB free for Docker.
set -u

MIN_DOCKER_HARD=25
MIN_DOCKER_WANTED=29
MIN_COMPOSE=2.24
MIN_CPUS=4
REC_CPUS=8
# An "8 GB" machine reports about 7.6 to 7.8 GiB in MemTotal (the kernel keeps the rest), so the minimum is in MiB.
MIN_MEM_MB=7400
REC_MEM_MB=15000
MIN_FREE_GB=100

# Hosts of plan section 2.4 that the updaters, the GitHub poller and the image pulls need.
NETWORK_HOSTS="github.com api.github.com login.microsoftonline.com registry-1.docker.io auth.docker.io ghcr.io quay.io
grype.anchore.io toolbox-data.anchore.io raw.githubusercontent.com api.pdtm.sh"

FAILS=0
WARNS=0

ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '[FAIL] %s\n' "$*"; FAILS=$((FAILS + 1)); }

# version_ge A B: true when version A >= version B (dotted numbers, an optional leading "v" is ignored).
version_ge() {
  a=${1#v}
  b=${2#v}
  [ "$(printf '%s\n%s\n' "$b" "$a" | sort -V | head -n 1)" = "$b" ]
}

check_os() {
  if [ "$(uname -s)" != "Linux" ]; then
    fail "This is $(uname -s), not Linux. SecureScan runs on a 64-bit Linux machine with systemd (Ubuntu 24.04 is the reference)."
    return
  fi
  case "$(uname -m)" in
    x86_64|aarch64) ok "Linux $(uname -r) on $(uname -m)" ;;
    *) fail "Unsupported architecture $(uname -m); the pinned images need x86_64 or aarch64." ;;
  esac
  if [ -d /run/systemd/system ]; then ok "systemd is the init system"; else warn "systemd was not detected; the install guide assumes it (restart policy, timers)."; fi
}

check_cgroup() {
  fstype=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)
  if [ "$fstype" = "cgroup2fs" ]; then
    ok "cgroup v2 is mounted at /sys/fs/cgroup"
  else
    fail "cgroup v2 is not in use (/sys/fs/cgroup is $fstype). Container memory, CPU and PID limits need it: boot with systemd.unified_cgroup_hierarchy=1."
    return
  fi
  controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true)
  for c in memory pids cpu; do
    case " $controllers " in
      *" $c "*) ok "cgroup controller $c is available" ;;
      *) if [ "$c" = cpu ]; then warn "cgroup controller cpu is not available: CPU limits will not be enforced."; else fail "cgroup controller $c is not available: its limit will not be enforced."; fi ;;
    esac
  done
}

check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker is not installed (or not on PATH)."
    return
  fi
  server=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
  if [ -z "$server" ]; then
    fail "Cannot talk to the Docker daemon. Is it running, and is this user in the docker group (or root)?"
    return
  fi
  major=${server%%.*}
  if [ "$major" -lt "$MIN_DOCKER_HARD" ] 2>/dev/null; then
    fail "Docker Engine $server is older than $MIN_DOCKER_HARD, which the worker cannot use (Docker API 1.44)."
  elif [ "$major" -lt "$MIN_DOCKER_WANTED" ] 2>/dev/null; then
    warn "Docker Engine $server works but this release was written for $MIN_DOCKER_WANTED or later."
  else
    ok "Docker Engine $server"
  fi
  compose=$(docker compose version --short 2>/dev/null || true)
  if [ -z "$compose" ]; then
    fail "The Docker Compose plugin is missing (docker compose version failed). Install docker-compose-plugin."
  elif version_ge "$compose" "$MIN_COMPOSE"; then
    ok "Docker Compose $compose (needs $MIN_COMPOSE for include and !reset)"
  else
    fail "Docker Compose $compose is older than $MIN_COMPOSE (needed for include, !reset and !override)."
  fi
  cgv=$(docker info --format '{{.CgroupVersion}}' 2>/dev/null || true)
  if [ "$cgv" = "2" ]; then ok "Docker reports cgroup version 2"; elif [ -n "$cgv" ]; then fail "Docker reports cgroup version $cgv."; fi
  drv=$(docker info --format '{{.CgroupDriver}}' 2>/dev/null || true)
  if [ "$drv" = "systemd" ]; then ok "Docker uses the systemd cgroup driver"; elif [ -n "$drv" ]; then warn "Docker uses the $drv cgroup driver; systemd is the supported one on a systemd host."; fi
  rootless=$(docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' 2>/dev/null | grep -c rootless || true)
  if [ "$rootless" -gt 0 ]; then warn "Docker runs rootless. That is allowed (stronger isolation) but the socket proxy bind-mount path and ports below 1024 need attention; see docs/install.md."; fi
  root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
  if [ -n "$root" ] && [ -d "$root" ]; then
    free_kb=$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$free_kb" ]; then
      free_gb=$((free_kb / 1024 / 1024))
      if [ "$free_gb" -ge "$MIN_FREE_GB" ]; then ok "$free_gb GB free under $root"; else warn "Only $free_gb GB free under $root; plan for $MIN_FREE_GB GB or more (images, volumes, five years of history)."; fi
    fi
  fi
  sock_gid=$(stat -c %g /var/run/docker.sock 2>/dev/null || true)
  if [ -n "$sock_gid" ]; then ok "Docker socket group id is $sock_gid (for SOCKET_PROXY_USER=65534:$sock_gid in deploy/.env)"; fi
}

check_resources() {
  cpus=$(nproc 2>/dev/null || echo 0)
  if [ "$cpus" -ge "$REC_CPUS" ]; then ok "$cpus CPUs"; elif [ "$cpus" -ge "$MIN_CPUS" ]; then ok "$cpus CPUs (the minimum; scans run one at a time)"; else fail "$cpus CPUs; the minimum is $MIN_CPUS."; fi
  mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  mem_mb=$((mem_kb / 1024))
  if [ "$mem_mb" -ge "$REC_MEM_MB" ]; then ok "$mem_mb MB memory"; elif [ "$mem_mb" -ge "$MIN_MEM_MB" ]; then ok "$mem_mb MB memory (the minimum; scans run one at a time)"; else fail "$mem_mb MB memory; the minimum is an 8 GB machine ($MIN_MEM_MB MB visible)."; fi
  swap_kb=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$swap_kb" -gt 0 ]; then warn "Swap is on. Container memory limits then allow swapping; consider swapoff or vm.swappiness=1."; fi
}

check_time() {
  if command -v timedatectl >/dev/null 2>&1; then
    synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [ "$synced" = "yes" ]; then ok "The clock is synchronised (NTP)"; elif [ -n "$synced" ]; then warn "The clock is not NTP-synchronised. Sign-in tokens, GitHub App tokens and certificates depend on correct time."; fi
  fi
}

check_network() {
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is missing; skipping the network test."
    return
  fi
  for host in $NETWORK_HOSTS; do
    code=$(curl -sS -o /dev/null -m 10 -w '%{http_code}' -I "https://$host/" 2>/dev/null || true)
    case "$code" in
      000|"") fail "Cannot reach https://$host/ (no answer). Open it in the firewall for the egress proxy." ;;
      *) ok "https://$host/ answers ($code)" ;;
    esac
  done
}

main() {
  want_network=0
  for arg in "$@"; do
    case "$arg" in
      --network) want_network=1 ;;
      -h|--help) sed -n '2,15p' "$0"; return 0 ;;
      *) printf 'unknown argument: %s\n' "$arg" >&2; return 2 ;;
    esac
  done
  check_os
  [ "$(uname -s)" = "Linux" ] || { printf '\n%d failure(s), %d warning(s)\n' "$FAILS" "$WARNS"; return 1; }
  check_cgroup
  check_docker
  check_resources
  check_time
  [ "$want_network" -eq 1 ] && check_network
  printf '\n%d failure(s), %d warning(s)\n' "$FAILS" "$WARNS"
  [ "$FAILS" -eq 0 ]
}

# Run only when executed, so the functions can be sourced by a test.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
