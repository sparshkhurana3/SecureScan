#!/bin/sh
# Spike S7: scanner container contract. Runs every pinned scanner image with the M3 hardening flags against the planted apps,
# records uid, writable paths, exit codes and output files, and writes the reports into backend/tests/fixtures/reports/.
#
#   sh spikes/s7/prefetch.sh all            # once, with network: pull images, Grype DB, Nuclei templates, Semgrep rules
#   NVD_API_KEY=... sh spikes/s7/odc_update.sh   # start FIRST, runs 20+ minutes in the background
#   sh spikes/s7/build_spotbugs.sh          # builds securescan/spotbugs-fsb (needs the two checksums, see scanners/spotbugs/README.md)
#   sh spikes/s7/run_all.sh                 # all tools
#   sh spikes/s7/run_all.sh semgrep gitleaks syft grype      # a subset (names below)
#
# Tools: semgrep gitleaks syft grype dependency-check spotbugs zap nuclei   (sonarqube is spike S3: spikes/s3/run.py)
#
# Environment (all optional)
#   S7_APPS            space-separated sample apps (default: java-planted js-planted python-planted csharp-planted)
#   S7_WRITE_FIXTURES  1 (default) copies the chosen report per tool into backend/tests/fixtures/reports/
#   S7_FIXTURE_APP_<TOOL>   app whose report becomes the fixture; defaults: semgrep js-planted; gitleaks, grype,
#                      dependency-check, spotbugs java-planted   (names upper-case, - and . replaced by _ : DEPENDENCY_CHECK)
#   S7_JUICESHOP_IMAGE target for zap and nuclei (default bkimminich/juice-shop; a throwaway target, not a platform image)
#   S7_NUCLEI_TAGS     default "tech,exposure,misconfig";  S7_NUCLEI_SEVERITY default "info,low,medium,high,critical"
#   S7_ODC_CONCURRENT  1 (default) also runs two Dependency-Check containers at the same time on the same data volume
#   S7_UTIL_IMAGE      small image used for cleanup and chmod (default busybox:1.37)
#   IMG_<NAME>         image references; read from deploy/images.env when present (python scripts/dev.py pin-images), else
#                      the tags of deploy/images.lock.yaml below
#
# What is recorded per tool (printed at the end as markdown rows for docs/spikes/s7-scanner-contract.md and kept in
# spikes/s7/.data/results.tsv): configured user and runtime uid, HOME, paths the container wrote outside its mounts
# (`docker diff`, run once WITHOUT --read-only), whether the hardened run (read-only rootfs, caps dropped, no network,
# tmpfs) works and which tmpfs it needed, exit codes for a clean target, planted findings and broken input, output files
# with owner and mode, and whether the content volume can be read-only.
#
# The script never stops at the first failure: scanner exit codes ARE the data. It exits 1 at the end when a hardened run
# failed for a tool, or an expected output file is missing. Full logs: spikes/s7/.data/logs/.
# Needs Docker, POSIX sh, git, and (for the first run of each tool) the prefetch steps. The repository path must not contain spaces.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DATA="$HERE/.data"
case "$ROOT" in *" "*) echo "the repository path must not contain spaces" >&2; exit 2 ;; esac
mkdir -p "$DATA"

# Keep a transcript of the whole run (a pipeline hides the exit status in POSIX sh, so the child leaves it in a file).
if [ -z "${S7_LOGGED:-}" ]; then
  S7_LOGGED=1 sh "$0" "$@" 2>&1 | tee "$DATA/run-$(date +%Y%m%dT%H%M%S).log"
  rc=1; [ -f "$DATA/.rc" ] && rc=$(cat "$DATA/.rc")
  exit "$rc"
fi
rm -f "$DATA/.rc"

APPS_DIR="$ROOT/backend/tests/fixtures/sample-apps"
REPORTS="$ROOT/backend/tests/fixtures/reports"
WS="$DATA/ws"
LOGS="$DATA/logs"
RES="$DATA/results.tsv"
CONTENT="$DATA/content"
UTIL=${S7_UTIL_IMAGE:-busybox:1.37}
APPS_LIST=${S7_APPS:-"java-planted js-planted python-planted csharp-planted"}
WRITE_FIX=${S7_WRITE_FIXTURES:-1}
JUICE=${S7_JUICESHOP_IMAGE:-bkimminich/juice-shop}
NUCLEI_TAGS=${S7_NUCLEI_TAGS:-tech,exposure,misconfig}
NUCLEI_SEV=${S7_NUCLEI_SEVERITY:-info,low,medium,high,critical}
ODC_CONC=${S7_ODC_CONCURRENT:-1}
FAILED=0

# ---------------------------------------------------------------- images
if [ -f "$ROOT/deploy/images.env" ]; then
  set -a; . "$ROOT/deploy/images.env"; set +a
fi
: "${IMG_SEMGREP:=semgrep/semgrep:1.179.0-nonroot}"
: "${IMG_GITLEAKS:=ghcr.io/gitleaks/gitleaks:v8.30.1}"
: "${IMG_SYFT:=anchore/syft:v1.54.0}"
: "${IMG_GRYPE:=anchore/grype:v0.120.0}"
: "${IMG_DEPENDENCY_CHECK:=owasp/dependency-check:13.0.0}"
: "${IMG_SPOTBUGS_FSB:=securescan/spotbugs-fsb:4.10.4-1.14.0}"
: "${IMG_ZAP:=ghcr.io/zaproxy/zaproxy:stable}"
: "${IMG_NUCLEI:=projectdiscovery/nuclei:v3.11.1}"
# Local tag for the self-built image even if images.env pins something else.
[ -n "${S7_SPOTBUGS_IMAGE:-}" ] && IMG_SPOTBUGS_FSB=$S7_SPOTBUGS_IMAGE

# ---------------------------------------------------------------- helpers
say() { printf '%s\n' "$*"; }
hdr() { printf '\n==== %s ====\n' "$*"; }

record() { # tool app scenario exit note
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RES"
  printf 'RESULT tool=%s app=%s scenario=%s exit=%s %s\n' "$1" "$2" "$3" "$4" "$5"
}

fact() { # tool key value
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "-" "fact:$2" "-" "$3" >> "$RES"
  printf 'FACT %s.%s = %s\n' "$1" "$2" "$3"
}

util_rm() { # remove root-owned leftovers (paths relative to $DATA) of earlier runs through a container
  ur_args=""
  for ur_p in "$@"; do ur_args="$ur_args /d/$ur_p"; done
  docker run --rm -v "$DATA:/d" "$UTIL" sh -c "rm -rf $ur_args" >/dev/null 2>&1 || true
}

image_user() { docker image inspect -f '{{.Config.User}}' "$1" 2>/dev/null; }
image_entrypoint_len() { docker image inspect -f '{{len .Config.Entrypoint}}' "$1" 2>/dev/null; }
image_home() { docker run --rm --entrypoint sh "$1" -c 'echo "$HOME"' 2>/dev/null | tail -n 1; }
bin_prefix() { # image binary: prints the binary name when the image has no entrypoint
  if [ "$(image_entrypoint_len "$1")" = "0" ]; then printf '%s' "$2"; fi
}

need_image() { # image: local or pullable? (the script never pulls; prefetch does)
  if ! docker image inspect "$1" >/dev/null 2>&1; then
    say "MISSING IMAGE: $1 (run: sh spikes/s7/prefetch.sh images)"
    return 1
  fi
}

runtime_uid() { # image [user]: uid and gid the process really gets, if the image has `id`
  if [ -n "${2:-}" ]; then
    docker run --rm --user "$2" --entrypoint id "$1" 2>&1 | head -n 1
  else
    docker run --rm --entrypoint id "$1" 2>&1 | head -n 1
  fi
}

# Docker options of the M3 HostConfig, from the H_* variables the tool function sets.
#   H_USER H_NET H_MEM H_CPUS H_TMPFS (space separated tmpfs specs) H_MOUNTS (host:container:mode) H_ENV (K=V) H_EXTRA
build_opts() { # hardened | discover
  printf -- '--cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory %s --cpus %s --network %s' \
    "${H_MEM:-4g}" "${H_CPUS:-2}" "${H_NET:-none}"
  [ -n "${H_USER:-}" ] && printf -- ' --user %s' "$H_USER"
  if [ "$1" = hardened ]; then
    printf -- ' --read-only'
    for t in ${H_TMPFS:-}; do printf -- ' --tmpfs %s' "$t"; done
  fi
  for m in ${H_MOUNTS:-}; do printf -- ' -v %s' "$m"; done
  for e in ${H_ENV:-}; do printf -- ' -e %s' "$e"; done
  [ -n "${H_EXTRA:-}" ] && printf -- ' %s' "$H_EXTRA"
  printf ' '
}

run_hardened() { # label image args...   -> sets RC
  rh_label=$1; rh_image=$2; shift 2
  rh_log="$LOGS/$rh_label.log"
  # shellcheck disable=SC2046
  docker run --rm --name "s7-$rh_label-$$" $(build_opts hardened) "$rh_image" "$@" > "$rh_log" 2>&1
  RC=$?
  tail -n "${S7_TAIL:-12}" "$rh_log" | sed 's/^/    | /'
  say "    exit code: $RC   (full log: $rh_log)"
}

discover_writes() { # label image args...   one run WITHOUT --read-only and tmpfs; lists what the container wrote
  dw_label=$1; dw_image=$2; shift 2
  dw_name="s7-disc-$dw_label-$$"
  # shellcheck disable=SC2046
  docker run --name "$dw_name" $(build_opts discover) "$dw_image" "$@" > "$LOGS/$dw_label.disc.log" 2>&1
  DW_RC=$?
  docker diff "$dw_name" > "$LOGS/$dw_label.diff" 2>/dev/null
  docker rm -f "$dw_name" >/dev/null 2>&1
  say "    discovery run exit code: $DW_RC; paths written outside the mounts (docker diff, A=added C=changed):"
  grep -v -E '^C /(dev|proc|sys|etc/(hosts|hostname|resolv.conf|mtab))' "$LOGS/$dw_label.diff" | head -n 25 | sed 's/^/    | /'
  DW_PATHS=$(grep -E '^[AC] ' "$LOGS/$dw_label.diff" | grep -v -E '^C /(dev|proc|sys|etc/(hosts|hostname|resolv.conf|mtab))$' \
    | awk '{print $2}' | head -n 12 | tr '\n' ' ')
}

# Runs the hardened command; if the exit code is not acceptable, retries once with `exec` on the tmpfs mounts
# (JVM and native-library tools often unpack into /tmp). $OK is the list of acceptable exit codes.
run_with_ladder() { # label image args...   uses OK, H_TMPFS
  rl_label=$1; rl_image=$2; shift 2
  run_hardened "$rl_label" "$rl_image" "$@"
  LADDER_NOTE="noexec-tmpfs"
  case " $OK " in *" $RC "*) return 0 ;; esac
  rl_first=$RC
  rl_saved=$H_TMPFS
  H_TMPFS=$(printf '%s\n' "$H_TMPFS" | sed -e 's/,exec//g' -e 's#[^ ][^ ]*#&,exec#g')
  say "    retrying with exec on the tmpfs mounts"
  run_hardened "$rl_label-exec" "$rl_image" "$@"
  H_TMPFS=$rl_saved
  LADDER_NOTE="first(noexec)=$rl_first retry(exec)=$RC"
  case " $OK " in *" $RC "*) LADDER_NOTE="$LADDER_NOTE; tmpfs needs exec" ;; esac
}

prep_ws() { # tool app -> SRC OUT CFG (world-writable, as the M3 workspace dirs are group-writable for uid 1000)
  pw_base="$WS/$2/$1"
  rm -rf "$pw_base" 2>/dev/null || util_rm "ws/$2/$1"
  mkdir -p "$pw_base/src" "$pw_base/out" "$pw_base/config"
  if [ "$2" = "_clean" ]; then
    printf 'nothing to see here\n' > "$pw_base/src/README.txt"
  else
    cp -R "$APPS_DIR/$2/." "$pw_base/src/"
    rm -f "$pw_base/src/expected-findings.yaml"
  fi
  chmod -R a+rwX "$pw_base"
  SRC="$pw_base/src"; OUT="$pw_base/out"; CFG="$pw_base/config"
}

list_outputs() { # dir
  ls -ln "$1" 2>/dev/null | awk 'NR>1 {print "    " $0}' | head -n 12
}

out_stat() { # file -> "uid:gid mode size"
  stat -c '%u:%g %a %s bytes' "$1" 2>/dev/null || echo "missing"
}

check_flags() { # label image "help command words" flag...   verifies that the pinned image knows the flags the plan uses
  cf_label=$1; cf_image=$2; cf_help=$3; shift 3
  # shellcheck disable=SC2086
  cf_text=$(docker run --rm --network none "$cf_image" $cf_help 2>&1 | head -n 800)
  cf_missing=""
  for f in "$@"; do
    printf '%s' "$cf_text" | grep -q -e "$f" || cf_missing="$cf_missing $f"
  done
  if [ -n "$cf_missing" ]; then
    say "    FLAGS NOT FOUND in '$cf_help' output of $cf_label:$cf_missing"
    fact "$cf_label" "flags_not_in_help" "$cf_missing"
  else
    say "    all plan flags are listed in the help output of $cf_label"
    fact "$cf_label" "flags_not_in_help" "none"
  fi
}

describe_image() { # tool image
  di_user=$(image_user "$2")
  fact "$1" "image" "$2"
  fact "$1" "configured_user" "${di_user:-<empty: root>}"
  fact "$1" "entrypoint_len" "$(image_entrypoint_len "$2")"
  fact "$1" "HOME" "$(image_home "$2")"
  fact "$1" "runtime_id" "$(runtime_uid "$2" "")"
  say "    entrypoint/cmd: $(docker image inspect -f '{{.Config.Entrypoint}} | {{.Config.Cmd}}' "$2")"
}

# ---------------------------------------------------------------- semgrep
tool_semgrep() {
  hdr "semgrep ($IMG_SEMGREP)"
  need_image "$IMG_SEMGREP" || { FAILED=1; return; }
  if [ ! -d "$CONTENT/semgrep-rules" ]; then say "no rules: run sh spikes/s7/prefetch.sh semgrep"; FAILED=1; return; fi
  describe_image semgrep "$IMG_SEMGREP"
  sg_bin=$(bin_prefix "$IMG_SEMGREP" semgrep)
  check_flags semgrep "$IMG_SEMGREP" "$sg_bin scan --help" --metrics --disable-version-check --json-output --sarif-output \
    --timeout --timeout-threshold --max-memory --jobs --config
  sg_home=$(image_home "$IMG_SEMGREP")
  H_USER=""; H_NET=none; H_MEM=4g; H_CPUS=2
  H_TMPFS="/tmp:rw,size=512m,mode=1777"
  case "$sg_home" in ""|"/"|"/root") : ;; *) H_TMPFS="$H_TMPFS $sg_home:rw,size=64m,mode=1777" ;; esac
  for app in $APPS_LIST _clean; do
    prep_ws semgrep "$app"
    H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CONTENT/semgrep-rules:/content/semgrep/rules:ro"
    H_ENV=""
    sg_cmd="$sg_bin scan --config /content/semgrep/rules --metrics=off --disable-version-check --json-output=/out/semgrep.json --sarif-output=/out/semgrep.sarif --timeout 30 --timeout-threshold 3 --max-memory 3000 --jobs 2 /src"
    if [ "$app" = "java-planted" ] || [ "$app" = "_clean" ]; then
      say "  -- $app: discovery of writable paths"
      # shellcheck disable=SC2086
      discover_writes "semgrep-$app" "$IMG_SEMGREP" $sg_cmd
      fact semgrep "writable_paths[$app]" "$DW_PATHS"
      chmod -R a+rwX "$OUT"; rm -rf "$OUT"/* 2>/dev/null || true
    fi
    say "  -- $app: hardened run"
    OK="0"
    # shellcheck disable=SC2086
    run_with_ladder "semgrep-$app" "$IMG_SEMGREP" $sg_cmd
    record semgrep "$app" "$([ "$app" = _clean ] && echo clean || echo findings)" "$RC" "$LADDER_NOTE; json=$(out_stat "$OUT/semgrep.json") sarif=$(out_stat "$OUT/semgrep.sarif")"
    [ "$RC" != "0" ] && FAILED=1
    list_outputs "$OUT"
  done
  say "  -- broken input (--config /does/not/exist)"
  prep_ws semgrep _clean
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
  OK="0"
  run_hardened "semgrep-broken" "$IMG_SEMGREP" $sg_bin scan --config /does/not/exist --metrics=off --disable-version-check --json-output=/out/semgrep.json /src
  record semgrep _clean broken "$RC" "expected non-zero"
}

# ---------------------------------------------------------------- gitleaks
make_git_repo() { # dir
  ( cd "$1" && git init -q && git add -A && git -c user.email=s7@example.invalid -c user.name=s7 commit -q -m "s7 planted app" ) >/dev/null 2>&1
  chmod -R a+rwX "$1"
}

tool_gitleaks() {
  hdr "gitleaks ($IMG_GITLEAKS)"
  need_image "$IMG_GITLEAKS" || { FAILED=1; return; }
  describe_image gitleaks "$IMG_GITLEAKS"
  gl_bin=$(bin_prefix "$IMG_GITLEAKS" gitleaks)
  check_flags gitleaks "$IMG_GITLEAKS" "$gl_bin git --help" --redact --config --ignore-gitleaks-allow --max-archive-depth \
    --report-format --report-path --exit-code
  H_USER=""; H_NET=none; H_MEM=1g; H_CPUS=1
  H_TMPFS="/tmp:rw,size=256m,mode=1777"; H_ENV=""
  for app in $APPS_LIST _clean; do
    for mode in dir git; do
      prep_ws gitleaks "$app"
      printf '[extend]\nuseDefault = true\n' > "$CFG/gitleaks.toml"
      [ "$mode" = git ] && make_git_repo "$SRC"
      H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro"
      gl_cmd="$gl_bin $mode /src --redact --config /config/gitleaks.toml --ignore-gitleaks-allow --max-archive-depth 2 --report-format json --report-path /out/gitleaks.json --exit-code 2"
      if [ "$app" = "java-planted" ] && [ "$mode" = git ]; then
        say "  -- $app ($mode): discovery of writable paths"
        # shellcheck disable=SC2086
        discover_writes "gitleaks-$app-$mode" "$IMG_GITLEAKS" $gl_cmd
        fact gitleaks "writable_paths[$mode]" "$DW_PATHS"
        rm -rf "$OUT"/* 2>/dev/null || true
      fi
      say "  -- $app ($mode): hardened run as the image's default user"
      OK="0 2"
      # shellcheck disable=SC2086
      run_with_ladder "gitleaks-$app-$mode" "$IMG_GITLEAKS" $gl_cmd
      gl_rc=$RC; gl_note=$LADDER_NOTE
      gl_scn=findings; [ "$app" = _clean ] && gl_scn=clean
      record gitleaks "$app" "$gl_scn/$mode" "$gl_rc" "$gl_note; json=$(out_stat "$OUT/gitleaks.json")"
      case "$gl_rc" in 0|2) : ;; *) FAILED=1 ;; esac
      list_outputs "$OUT"
      if [ "$mode" = git ] && [ "$gl_rc" != "0" ] && [ "$gl_rc" != "2" ]; then
        say "  -- $app (git): retry with safe.directory through GIT_CONFIG_* (repo owner differs from the container user)"
        H_ENV="GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/src"
        # shellcheck disable=SC2086
        run_hardened "gitleaks-$app-$mode-safe" "$IMG_GITLEAKS" $gl_cmd
        record gitleaks "$app" "$gl_scn/$mode+safe.directory" "$RC" "GIT_CONFIG_* env"
        H_ENV=""
      fi
    done
  done
  # non-root run (uid 1000) against a git repo: does it work, and does it need safe.directory?
  say "  -- non-root run (uid 1000:1000) against a git repository, without and with safe.directory"
  prep_ws gitleaks java-planted
  printf '[extend]\nuseDefault = true\n' > "$CFG/gitleaks.toml"
  make_git_repo "$SRC"
  H_USER="1000:1000"; H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro"; H_ENV=""
  gl_cmd="$gl_bin git /src --redact --config /config/gitleaks.toml --ignore-gitleaks-allow --report-format json --report-path /out/gitleaks.json --exit-code 2"
  # shellcheck disable=SC2086
  run_hardened "gitleaks-nonroot" "$IMG_GITLEAKS" $gl_cmd
  record gitleaks java-planted nonroot-git "$RC" "uid 1000, no safe.directory"
  H_ENV="GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/src"
  # shellcheck disable=SC2086
  run_hardened "gitleaks-nonroot-safe" "$IMG_GITLEAKS" $gl_cmd
  record gitleaks java-planted nonroot-git+safe "$RC" "uid 1000, GIT_CONFIG_* safe.directory"
  H_USER=""; H_ENV=""
  say "  -- broken input (path does not exist)"
  prep_ws gitleaks _clean
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
  run_hardened "gitleaks-broken" "$IMG_GITLEAKS" $gl_bin dir /does/not/exist --report-format json --report-path /out/gitleaks.json --exit-code 2
  record gitleaks _clean broken "$RC" "expected non-zero (plan maps 1 and 126 to failed)"
}

# ---------------------------------------------------------------- syft and grype
tool_syft() {
  hdr "syft ($IMG_SYFT)"
  need_image "$IMG_SYFT" || { FAILED=1; return; }
  describe_image syft "$IMG_SYFT"
  sy_bin=$(bin_prefix "$IMG_SYFT" syft)
  check_flags syft "$IMG_SYFT" "$sy_bin scan --help" --output
  H_USER=""; H_NET=none; H_MEM=2g; H_CPUS=1
  H_TMPFS="/tmp:rw,size=1g,mode=1777"; H_ENV="SYFT_CHECK_FOR_APP_UPDATE=false"
  for app in $APPS_LIST _clean; do
    prep_ws syft "$app"
    H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
    sy_cmd="$sy_bin scan dir:/src -o syft-json=/out/sbom.syft.json -o cyclonedx-json=/out/sbom.cdx.json"
    if [ "$app" = "java-planted" ]; then
      say "  -- $app: discovery of writable paths"
      # shellcheck disable=SC2086
      discover_writes "syft-$app" "$IMG_SYFT" $sy_cmd
      fact syft "writable_paths" "$DW_PATHS"
      rm -rf "$OUT"/* 2>/dev/null || true
    fi
    say "  -- $app: hardened run"
    OK="0"
    # shellcheck disable=SC2086
    run_with_ladder "syft-$app" "$IMG_SYFT" $sy_cmd
    sy_scn=findings; [ "$app" = _clean ] && sy_scn=clean
    record syft "$app" "$sy_scn" "$RC" "$LADDER_NOTE; sbom=$(out_stat "$OUT/sbom.syft.json") cdx=$(out_stat "$OUT/sbom.cdx.json")"
    [ "$RC" != "0" ] && FAILED=1
    list_outputs "$OUT"
  done
  say "  -- broken input (dir:/does/not/exist)"
  prep_ws syft _clean
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
  run_hardened "syft-broken" "$IMG_SYFT" $sy_bin scan dir:/does/not/exist -o syft-json=/out/sbom.syft.json
  record syft _clean broken "$RC" "expected non-zero"
}

tool_grype() {
  hdr "grype ($IMG_GRYPE)"
  need_image "$IMG_GRYPE" || { FAILED=1; return; }
  if ! docker volume inspect s7_grype_db >/dev/null 2>&1; then say "no Grype DB volume: run sh spikes/s7/prefetch.sh grype"; FAILED=1; return; fi
  describe_image grype "$IMG_GRYPE"
  gy_bin=$(bin_prefix "$IMG_GRYPE" grype)
  check_flags grype "$IMG_GRYPE" "$gy_bin --help" --output --fail-on
  H_USER=""; H_NET=none; H_MEM=2g; H_CPUS=1
  H_TMPFS="/tmp:rw,size=512m,mode=1777"
  H_ENV="GRYPE_DB_CACHE_DIR=/content/grype-db GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=true GRYPE_CHECK_FOR_APP_UPDATE=false"
  for app in $APPS_LIST _clean; do
    # the SBOM comes from the syft run of the same app (same out directory layout as the M8 'syft-grype' job)
    if [ ! -f "$WS/$app/syft/out/sbom.syft.json" ]; then say "  -- $app: no SBOM from the syft step, skipped (run syft first)"; continue; fi
    gy_base="$WS/$app/grype"; rm -rf "$gy_base" 2>/dev/null || util_rm "ws/$app/grype"
    mkdir -p "$gy_base/out"; cp "$WS/$app/syft/out/sbom.syft.json" "$gy_base/out/"; chmod -R a+rwX "$gy_base"
    OUT="$gy_base/out"
    gy_cmd="$gy_bin sbom:/out/sbom.syft.json -o json=/out/grype.json"
    say "  -- $app: hardened run, Grype DB volume mounted READ-ONLY"
    H_MOUNTS="$OUT:/out:rw s7_grype_db:/content/grype-db:ro"
    OK="0"
    # shellcheck disable=SC2086
    run_with_ladder "grype-$app" "$IMG_GRYPE" $gy_cmd
    gy_scn=findings; [ "$app" = _clean ] && gy_scn=clean
    gy_ro=$RC
    record grype "$app" "$gy_scn" "$RC" "db volume ro; $LADDER_NOTE; json=$(out_stat "$OUT/grype.json")"
    if [ "$gy_ro" != "0" ]; then
      say "  -- $app: retry with the DB volume read-write"
      H_MOUNTS="$OUT:/out:rw s7_grype_db:/content/grype-db:rw"
      # shellcheck disable=SC2086
      run_hardened "grype-$app-rw" "$IMG_GRYPE" $gy_cmd
      record grype "$app" "$gy_scn/db-rw" "$RC" "db volume rw"
      fact grype "db_volume_can_be_readonly" "no (ro exit $gy_ro, rw exit $RC)"
      [ "$RC" != "0" ] && FAILED=1
    else
      fact grype "db_volume_can_be_readonly" "yes"
    fi
    if [ "$app" = "java-planted" ]; then
      say "  -- $app: exit code with --fail-on high"
      H_MOUNTS="$OUT:/out:rw s7_grype_db:/content/grype-db:ro"
      # shellcheck disable=SC2086
      run_hardened "grype-$app-failon" "$IMG_GRYPE" $gy_cmd --fail-on high
      record grype "$app" "fail-on-high" "$RC" "exit code when asked to fail (documented: 1)"
      say "  -- $app: discovery of writable paths"
      # shellcheck disable=SC2086
      discover_writes "grype-$app" "$IMG_GRYPE" $gy_cmd
      fact grype "writable_paths" "$DW_PATHS"
    fi
    list_outputs "$OUT"
  done
  say "  -- broken input (sbom:/does/not/exist.json)"
  prep_ws grype _clean
  H_MOUNTS="$OUT:/out:rw s7_grype_db:/content/grype-db:ro"
  run_hardened "grype-broken" "$IMG_GRYPE" $gy_bin sbom:/does/not/exist.json -o json=/out/grype.json
  record grype _clean broken "$RC" "expected non-zero"
  say "  -- stale database check: GRYPE_DB_MAX_ALLOWED_BUILT_AGE=1h must make the run fail visibly"
  prep_ws grype _clean
  cp "$WS/_clean/syft/out/sbom.syft.json" "$OUT/" 2>/dev/null || printf '{}' > "$OUT/sbom.syft.json"
  chmod -R a+rwX "$OUT"
  H_ENV="$H_ENV GRYPE_DB_MAX_ALLOWED_BUILT_AGE=1h"
  H_MOUNTS="$OUT:/out:rw s7_grype_db:/content/grype-db:ro"
  run_hardened "grype-stale" "$IMG_GRYPE" $gy_bin sbom:/out/sbom.syft.json -o json=/out/grype.json
  record grype _clean stale-db "$RC" "expected non-zero with a message about database age"
}

# ---------------------------------------------------------------- dependency-check
tool_dependency_check() {
  hdr "dependency-check ($IMG_DEPENDENCY_CHECK)"
  need_image "$IMG_DEPENDENCY_CHECK" || { FAILED=1; return; }
  if [ "$(cat "$DATA/odc-update.done" 2>/dev/null)" != "0" ]; then
    say "the NVD update has not finished successfully (spikes/s7/.data/odc-update.done): start it with spikes/s7/odc_update.sh and wait"
    FAILED=1; return
  fi
  describe_image dependency-check "$IMG_DEPENDENCY_CHECK"
  dc_flags="--scan --format --out --project --noupdate --disableVersionCheck --disableOssIndex --disableNodeAudit --disableYarnAudit --disablePnpmAudit --propertyfile --data --disableCentral --nvdApiKey --updateonly"
  # shellcheck disable=SC2086
  check_flags dependency-check "$IMG_DEPENDENCY_CHECK" "--help" $dc_flags
  H_USER=""; H_NET=none; H_MEM=4g; H_CPUS=2
  H_TMPFS="/tmp:rw,size=1g,mode=1777"
  H_ENV=""
  # Optional switches are used only when the pinned image lists them in --help, so one renamed flag does not fail every run;
  # the dropped ones are recorded and must be reconciled with the plan's M8 command line.
  dc_help=$(docker run --rm --network none "$IMG_DEPENDENCY_CHECK" --help 2>&1)
  dc_opt=""; dc_dropped=""
  for dc_f in --disableVersionCheck --disableOssIndex --disableNodeAudit --disableYarnAudit --disablePnpmAudit --disableCentral; do
    if printf '%s' "$dc_help" | grep -q -e "$dc_f"; then dc_opt="$dc_opt $dc_f"; else dc_dropped="$dc_dropped $dc_f"; fi
  done
  fact dependency-check "optional_flags_dropped_because_not_in_help" "${dc_dropped:-none}"
  dc_common="--format XML --format HTML --out /out --noupdate$dc_opt --propertyfile /config/odc.properties --data /usr/share/dependency-check/data"
  for app in $APPS_LIST _clean; do
    prep_ws dependency-check "$app"
    : > "$CFG/odc.properties"
    chmod 0644 "$CFG/odc.properties"
    H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro s7_odc_data:/usr/share/dependency-check/data:ro"
    dc_cmd="--scan /src --project s7-$app $dc_common"
    if [ "$app" = "java-planted" ]; then
      say "  -- $app: discovery of writable paths (data volume mounted read-write for this run)"
      H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro s7_odc_data:/usr/share/dependency-check/data:rw"
      # shellcheck disable=SC2086
      discover_writes "dc-$app" "$IMG_DEPENDENCY_CHECK" $dc_cmd
      fact dependency-check "writable_paths" "$DW_PATHS"
      rm -rf "$OUT"/* 2>/dev/null || true
      H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro s7_odc_data:/usr/share/dependency-check/data:ro"
    fi
    say "  -- $app: hardened run, data volume READ-ONLY"
    OK="0 14"
    # shellcheck disable=SC2086
    run_with_ladder "dc-$app" "$IMG_DEPENDENCY_CHECK" $dc_cmd
    dc_ro=$RC; dc_note=$LADDER_NOTE
    dc_scn=findings; [ "$app" = _clean ] && dc_scn=clean
    record dependency-check "$app" "$dc_scn" "$RC" "data ro; $dc_note; xml=$(out_stat "$OUT/dependency-check-report.xml")"
    case "$dc_ro" in 0|14) fact dependency-check "data_volume_can_be_readonly" "yes (exit $dc_ro)" ;;
      *)
        say "  -- $app: retry with the data volume read-write"
        H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro s7_odc_data:/usr/share/dependency-check/data:rw"
        # shellcheck disable=SC2086
        run_with_ladder "dc-$app-rw" "$IMG_DEPENDENCY_CHECK" $dc_cmd
        record dependency-check "$app" "$dc_scn/data-rw" "$RC" "data rw; $LADDER_NOTE"
        fact dependency-check "data_volume_can_be_readonly" "no (ro exit $dc_ro, rw exit $RC)"
        case "$RC" in 0|14) : ;; *) FAILED=1 ;; esac ;;
    esac
    list_outputs "$OUT"
  done
  if [ "$ODC_CONC" = "1" ]; then
    say "  -- two concurrent Dependency-Check containers on the same data volume (read-only), different apps"
    prep_ws dependency-check-c1 java-planted; c1_src=$SRC; c1_out=$OUT; c1_cfg=$CFG; : > "$c1_cfg/odc.properties"
    prep_ws dependency-check-c2 js-planted; c2_src=$SRC; c2_out=$OUT; c2_cfg=$CFG; : > "$c2_cfg/odc.properties"
    chmod -R a+rwX "$c1_cfg" "$c2_cfg"
    docker run --rm --name "s7-dc-c1-$$" --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
      --tmpfs /tmp:rw,size=1g,mode=1777,exec -v "$c1_src:/src:ro" -v "$c1_out:/out:rw" -v "$c1_cfg:/config:ro" \
      -v s7_odc_data:/usr/share/dependency-check/data:ro "$IMG_DEPENDENCY_CHECK" --scan /src --project s7-c1 $dc_common \
      > "$LOGS/dc-concurrent-1.log" 2>&1 &
    c1_pid=$!
    docker run --rm --name "s7-dc-c2-$$" --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
      --tmpfs /tmp:rw,size=1g,mode=1777,exec -v "$c2_src:/src:ro" -v "$c2_out:/out:rw" -v "$c2_cfg:/config:ro" \
      -v s7_odc_data:/usr/share/dependency-check/data:ro "$IMG_DEPENDENCY_CHECK" --scan /src --project s7-c2 $dc_common \
      > "$LOGS/dc-concurrent-2.log" 2>&1 &
    c2_pid=$!
    wait "$c1_pid"; c1_rc=$?; wait "$c2_pid"; c2_rc=$?
    record dependency-check java-planted concurrent-1 "$c1_rc" "two containers, one shared ro volume"
    record dependency-check js-planted concurrent-2 "$c2_rc" "two containers, one shared ro volume"
    fact dependency-check "two_concurrent_containers_share_volume" "exit $c1_rc and $c2_rc (0 or 14 = works)"
  fi
  say "  -- broken input (--scan /does/not/exist)"
  prep_ws dependency-check _clean
  : > "$CFG/odc.properties"; chmod 0644 "$CFG/odc.properties"
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw $CFG:/config:ro s7_odc_data:/usr/share/dependency-check/data:ro"
  # shellcheck disable=SC2086
  run_hardened "dc-broken" "$IMG_DEPENDENCY_CHECK" --scan /does/not/exist --project s7-broken $dc_common
  record dependency-check _clean broken "$RC" "expected non-zero"
  say "  -- NVD key property name (the update run writes spikes/s7/.data/odc-update.log): see the lines about the API key there"
  grep -i -E 'api key|nvd.api|apikey' "$DATA/odc-update.log" 2>/dev/null | head -n 5 | sed 's/^/    | /'
}

# ---------------------------------------------------------------- spotbugs
tool_spotbugs() {
  hdr "spotbugs + find-sec-bugs ($IMG_SPOTBUGS_FSB)"
  need_image "$IMG_SPOTBUGS_FSB" || { say "build it: sh spikes/s7/build_spotbugs.sh"; FAILED=1; return; }
  if [ ! -f "$APPS_DIR/java-planted/target/java-planted.jar" ]; then
    say "backend/tests/fixtures/sample-apps/java-planted/target/java-planted.jar is missing: run sh scripts/build_planted_jar.sh (M0 step 3)"
    FAILED=1; return
  fi
  describe_image spotbugs "$IMG_SPOTBUGS_FSB"
  check_flags spotbugs "$IMG_SPOTBUGS_FSB" "-help" -textui -pluginList -effort -xml -output -low
  H_USER=""; H_NET=none; H_MEM=2g; H_CPUS=2
  H_TMPFS="/tmp:rw,size=512m,mode=1777"; H_ENV=""
  prep_ws spotbugs java-planted
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
  sb_a="-textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -xml:withMessages=/out/spotbugs.xml /src/target/java-planted.jar"
  sb_b="-textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -xml:withMessages -output /out/spotbugs.xml /src/target/java-planted.jar"
  say "  -- discovery of writable paths"
  # shellcheck disable=SC2086
  discover_writes "spotbugs" "$IMG_SPOTBUGS_FSB" $sb_a
  fact spotbugs "writable_paths" "$DW_PATHS"
  rm -rf "$OUT"/* 2>/dev/null || true
  say "  -- hardened run, form A: -xml:withMessages=/out/spotbugs.xml (the plan's form)"
  OK="0"
  # shellcheck disable=SC2086
  run_with_ladder "spotbugs-a" "$IMG_SPOTBUGS_FSB" $sb_a
  record spotbugs java-planted findings-formA "$RC" "$LADDER_NOTE; xml=$(out_stat "$OUT/spotbugs.xml")"
  if [ ! -s "$OUT/spotbugs.xml" ]; then
    say "  -- form A produced no file; hardened run, form B: -xml:withMessages -output /out/spotbugs.xml"
    # shellcheck disable=SC2086
    run_with_ladder "spotbugs-b" "$IMG_SPOTBUGS_FSB" $sb_b
    record spotbugs java-planted findings-formB "$RC" "$LADDER_NOTE; xml=$(out_stat "$OUT/spotbugs.xml")"
    fact spotbugs "output_option_that_works" "$([ -s "$OUT/spotbugs.xml" ] && echo "-xml:withMessages -output FILE" || echo none)"
  else
    fact spotbugs "output_option_that_works" "-xml:withMessages=FILE"
  fi
  [ -s "$OUT/spotbugs.xml" ] || FAILED=1
  list_outputs "$OUT"
  if [ -s "$OUT/spotbugs.xml" ]; then
    say "  bug types found by Find Security Bugs:"
    grep -o 'type="[A-Z_0-9]*"' "$OUT/spotbugs.xml" | sort | uniq -c | sort -rn | head -n 15 | sed 's/^/    | /'
  fi
  say "  -- clean target (an empty directory)"
  prep_ws spotbugs _clean
  H_MOUNTS="$SRC:/src:ro $OUT:/out:rw"
  run_hardened "spotbugs-clean" "$IMG_SPOTBUGS_FSB" -textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -xml:withMessages -output /out/spotbugs.xml /src
  record spotbugs _clean clean "$RC" "no classes: what does the tool do? (M8 skips the job instead)"
  say "  -- broken input (jar does not exist)"
  run_hardened "spotbugs-broken" "$IMG_SPOTBUGS_FSB" -textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -xml:withMessages -output /out/spotbugs.xml /src/does-not-exist.jar
  record spotbugs _clean broken "$RC" "expected non-zero or an empty report"
}

# ---------------------------------------------------------------- DAST target
juice_up() {
  docker network inspect s7-dast >/dev/null 2>&1 || docker network create --internal s7-dast >/dev/null
  if ! docker inspect s7-juiceshop >/dev/null 2>&1; then
    docker run -d --name s7-juiceshop --network s7-dast "$JUICE" >/dev/null || return 1
  fi
  ji=0
  until docker exec s7-juiceshop node -e "require('http').get('http://localhost:3000',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))" >/dev/null 2>&1; do
    ji=$((ji + 1)); [ "$ji" -gt 60 ] && { say "Juice Shop did not become ready"; return 1; }
    sleep 2
  done
  say "Juice Shop is up on the internal network s7-dast as http://s7-juiceshop:3000"
}

juice_down() { docker rm -f s7-juiceshop >/dev/null 2>&1; docker network rm s7-dast >/dev/null 2>&1; }

tool_zap() {
  hdr "zap ($IMG_ZAP)"
  need_image "$IMG_ZAP" || { FAILED=1; return; }
  need_image "$JUICE" || docker pull "$JUICE" || { FAILED=1; return; }
  juice_up || { FAILED=1; return; }
  describe_image zap "$IMG_ZAP"
  prep_ws zap _target
  cat > "$OUT/plan.yaml" <<'PLAN'
env:
  contexts:
    - name: juice
      urls: ["http://s7-juiceshop:3000"]
      includePaths: ["http://s7-juiceshop:3000.*"]
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true
jobs:
  - type: spider
    parameters:
      context: juice
      maxDuration: 2
      maxDepth: 4
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
  - type: report
    parameters:
      template: traditional-xml-plus
      reportDir: /zap/wrk
      reportFile: zap
      reportTitle: s7
PLAN
  chmod a+rw "$OUT/plan.yaml"
  H_USER=""; H_NET=s7-dast; H_MEM=4g; H_CPUS=2
  H_TMPFS="/tmp:rw,size=512m,mode=1777 /home/zap/.ZAP:rw,size=256m,mode=1777"
  H_ENV=""; H_MOUNTS="$OUT:/zap/wrk:rw"
  zp_cmd="zap.sh -cmd -autorun /zap/wrk/plan.yaml -silent"
  say "  -- discovery of writable paths (no read-only rootfs)"
  # shellcheck disable=SC2086
  discover_writes "zap" "$IMG_ZAP" $zp_cmd
  fact zap "writable_paths" "$DW_PATHS"
  ls "$OUT" | sed 's/^/    | out: /'
  rm -f "$OUT"/zap.* "$OUT"/*.xml "$OUT"/*.html 2>/dev/null || true
  say "  -- hardened run: read-only rootfs, internal network only"
  OK="0 1 2"
  # shellcheck disable=SC2086
  run_with_ladder "zap" "$IMG_ZAP" $zp_cmd
  record zap juice-shop baseline "$RC" "$LADDER_NOTE; xml=$(out_stat "$OUT/zap.xml")"
  list_outputs "$OUT"
  [ -s "$OUT/zap.xml" ] || { say "    zap.xml not produced: check the report job parameters and the log"; FAILED=1; }
  say "  -- broken input (plan file does not exist)"
  run_hardened "zap-broken" "$IMG_ZAP" zap.sh -cmd -autorun /zap/wrk/does-not-exist.yaml -silent
  record zap _target broken "$RC" "expected non-zero (plan maps other codes to failed)"
  say "  -- can ZAP reach the internet from the internal network? (it must not)"
  docker run --rm --network s7-dast --entrypoint sh "$IMG_ZAP" -c 'wget -q -T 5 -O /dev/null http://example.com && echo REACHED || echo not-reachable' 2>&1 | tail -n 1 | sed 's/^/    | /'
}

tool_nuclei() {
  hdr "nuclei ($IMG_NUCLEI)"
  need_image "$IMG_NUCLEI" || { FAILED=1; return; }
  if ! docker volume inspect s7_nuclei_templates >/dev/null 2>&1; then say "no templates volume: run sh spikes/s7/prefetch.sh nuclei"; FAILED=1; return; fi
  need_image "$JUICE" || docker pull "$JUICE" || { FAILED=1; return; }
  juice_up || { FAILED=1; return; }
  describe_image nuclei "$IMG_NUCLEI"
  nu_bin=$(bin_prefix "$IMG_NUCLEI" nuclei)
  check_flags nuclei "$IMG_NUCLEI" "$nu_bin -h" -duc -ni -dut -ud -etags -severity -rl -c -json-export -tags
  prep_ws nuclei _target
  H_USER=""; H_NET=s7-dast; H_MEM=2g; H_CPUS=2
  H_TMPFS="/tmp:rw,size=512m,mode=1777"
  H_ENV="NUCLEI_CONFIG_DIR=/tmp/nuclei-config"
  H_MOUNTS="$OUT:/out:rw s7_nuclei_templates:/content/nuclei-templates:ro"
  nu_cmd="$nu_bin -u http://s7-juiceshop:3000 -duc -ni -dut -ud /content/nuclei-templates -etags dos,fuzz,bruteforce,local,txt-service,intrusive -severity $NUCLEI_SEV -tags $NUCLEI_TAGS -rl 50 -c 10 -json-export /out/nuclei.json"
  say "  -- discovery of writable paths"
  # shellcheck disable=SC2086
  discover_writes "nuclei" "$IMG_NUCLEI" $nu_cmd
  fact nuclei "writable_paths" "$DW_PATHS"
  rm -rf "$OUT"/* 2>/dev/null || true
  say "  -- hardened run: read-only rootfs, templates volume read-only, internal network only"
  OK="0"
  # shellcheck disable=SC2086
  run_with_ladder "nuclei" "$IMG_NUCLEI" $nu_cmd
  record nuclei juice-shop findings "$RC" "$LADDER_NOTE; json=$(out_stat "$OUT/nuclei.json")"
  list_outputs "$OUT"
  [ -f "$OUT/nuclei.json" ] || { say "    nuclei.json not produced (nuclei may write the export only when there are results)"; FAILED=1; }
  say "  -- broken input (target that does not resolve)"
  run_hardened "nuclei-broken" "$IMG_NUCLEI" $nu_bin -u http://does-not-exist.invalid -duc -ni -dut -ud /content/nuclei-templates -json-export /out/nuclei-broken.json
  record nuclei _target broken "$RC" "expected 0 or non-zero: record which"
}

# ---------------------------------------------------------------- fixtures and summary
copy_fixture() { # tool app-dir-subpath source-file fixture-name
  [ "$WRITE_FIX" = "1" ] || return 0
  cf_src="$WS/$2/$3"
  if [ -s "$cf_src" ]; then
    mkdir -p "$REPORTS"
    cp "$cf_src" "$REPORTS/$4"
    say "fixture written: backend/tests/fixtures/reports/$4  (from $2, $(wc -c < "$cf_src") bytes)"
  else
    say "FIXTURE NOT WRITTEN: $cf_src missing or empty"
    FAILED=1
  fi
}

fixture_app() { # TOOLVAR default
  eval "fa_v=\${S7_FIXTURE_APP_$1:-$2}"
  printf '%s' "$fa_v"
}

write_fixtures() {
  hdr "fixtures"
  for t in $TOOLS; do
    case "$t" in
      semgrep) copy_fixture semgrep "$(fixture_app SEMGREP js-planted)/semgrep" out/semgrep.json semgrep.json ;;
      gitleaks) copy_fixture gitleaks "$(fixture_app GITLEAKS java-planted)/gitleaks" out/gitleaks.json gitleaks.json ;;
      grype) copy_fixture grype "$(fixture_app GRYPE java-planted)/grype" out/grype.json grype.json ;;
      dependency-check) copy_fixture dc "$(fixture_app DEPENDENCY_CHECK java-planted)/dependency-check" out/dependency-check-report.xml dependency-check-report.xml ;;
      spotbugs) copy_fixture spotbugs java-planted/spotbugs out/spotbugs.xml spotbugs.xml ;;
      zap) copy_fixture zap _target/zap out/zap.xml zap.xml ;;
      nuclei) copy_fixture nuclei _target/nuclei out/nuclei.json nuclei.json ;;
    esac
  done
  say "sonarqube-issues.zip is written by spikes/s3/run.py"
}

summary() {
  hdr "summary (paste into docs/spikes/s7-scanner-contract.md)"
  say "| tool | app / scenario | exit code | note |"
  say "| --- | --- | --- | --- |"
  grep -v -P '\tfact:' "$RES" | awk -F'\t' '{printf "| %s | %s / %s | %s | %s |\n", $1, $2, $3, $4, $5}'
  say ""
  say "| tool | fact | value |"
  say "| --- | --- | --- |"
  grep -P '\tfact:' "$RES" | awk -F'\t' '{k=$3; sub(/^fact:/,"",k); printf "| %s | %s | %s |\n", $1, k, $5}'
}

# ---------------------------------------------------------------- main
TOOLS="${*:-semgrep gitleaks syft grype dependency-check spotbugs zap nuclei}"
for t in $TOOLS; do
  case "$t" in semgrep|gitleaks|syft|grype|dependency-check|spotbugs|zap|nuclei) : ;;
    sonarqube) say "sonarqube is spike S3 (uv run --project backend python spikes/s3/run.py)"; ;;
    *) say "unknown tool: $t"; echo 2 > "$DATA/.rc"; exit 2 ;;
  esac
done
docker info >/dev/null 2>&1 || { say "docker is not available"; echo 2 > "$DATA/.rc"; exit 2; }
docker image inspect "$UTIL" >/dev/null 2>&1 || docker pull "$UTIL" >/dev/null
util_rm ws logs results.tsv
mkdir -p "$WS" "$LOGS"
: > "$RES"
say "S7 started $(date -u +%Y-%m-%dT%H:%M:%SZ); docker $(docker version -f '{{.Server.Version}}' 2>/dev/null); host uid $(id -u)"

for t in $TOOLS; do
  case "$t" in
    semgrep) tool_semgrep ;;
    gitleaks) tool_gitleaks ;;
    syft) tool_syft ;;
    grype) tool_grype ;;
    dependency-check) tool_dependency_check ;;
    spotbugs) tool_spotbugs ;;
    zap) tool_zap ;;
    nuclei) tool_nuclei ;;
  esac
done
case " $TOOLS " in *" zap "*|*" nuclei "*) juice_down ;; esac
write_fixtures
summary
say ""
if [ "$FAILED" -ne 0 ]; then say "S7 finished WITH PROBLEMS (see lines above); the data is still valid for the findings file."; else say "S7 finished: every hardened run worked."; fi
echo "$FAILED" > "$DATA/.rc"
exit "$FAILED"
