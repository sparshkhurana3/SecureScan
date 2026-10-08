#!/usr/bin/env bash
# Backs up SecureScan: the three PostgreSQL databases, the artifact, DefectDojo media and data volumes, a manifest
# of the content volume, the configuration (and, unless disabled, the Docker secrets), encrypts every part with
# age, copies the set off the machine, verifies the copy and records the time of the last success.
#
#   bash scripts/backup.sh                 # a full backup; exit 0 only when the set was copied off the machine and verified
#   bash scripts/backup.sh --check         # check the prerequisites and the settings, change nothing
#   bash scripts/backup.sh --no-offsite    # local set only (testing). The success metric is NOT updated
#   bash scripts/backup.sh --help
#
# Schedule it from the host's cron after the nightly quiet period (docs/runbooks/restore.md, docs/install.md):
#   30 1 * * *  root  cd /opt/securescan && bash scripts/backup.sh >> /var/log/securescan-backup.log 2>&1
#
# Settings: environment variables, or KEY=value lines in deploy/.env (the environment wins). None is a secret.
#   BACKUP_DIR              local directory for the backup sets             default /var/backups/securescan
#   BACKUP_REMOTE           where to copy the set: user@host:/path (rsync over ssh), or a directory (a mounted share)
#   BACKUP_REMOTE_METHOD    rsync | scp | copy                              default: rsync for user@host:/path, else copy
#   BACKUP_SSH_KEY          private key file for the remote host (BatchMode, no prompt)
#   BACKUP_SSH_KNOWN_HOSTS  known_hosts file for the remote host            default ~/.ssh/known_hosts
#   BACKUP_AGE_RECIPIENT    age public key (age1...)                        default: derived from the key file below
#   BACKUP_AGE_KEY_FILE     age identity file                               default deploy/secrets/backup_age_key
#   BACKUP_INCLUDE_SECRETS  true | false: put deploy/secrets in the set    default true (encrypted; see the runbook)
#   BACKUP_KEEP_DAYS        delete local sets older than this many days     default 7 (the two newest are always kept)
#   BACKUP_METRICS_FILE     also write a Prometheus text file here (node_exporter textfile collector)
#   BACKUP_IMAGE            image with tar and find for the volume reads    default IMG_PYTHON of deploy/images.env
#   BACKUP_PROJECT          Compose project name                            default securescan
#
# What is in a set (a directory of encrypted files; nothing unencrypted except MANIFEST.txt and SHA256SUMS):
#   db-securescan.dump.age db-defectdojo.dump.age db-sonarqube.dump.age   pg_dump --format=custom
#   db-globals.sql.age                                                      roles (pg_dumpall --globals-only)
#   artifacts.tar.age defectdojo_media.tar.age data.tar.age                 volumes (data without workspaces)
#   content-manifest.txt.age                                                what the content volume holds (not the rules)
#   config.tar.age                                                          deploy/.env, images.env, images.lock.yaml
#   secrets.tar.age                                                         deploy/secrets without the age key (optional)
#
# The age PRIVATE key must also be kept somewhere else (a vault, a sealed envelope): without it no backup can be read.
# Nothing is written unencrypted to disk, and no secret is printed.
set -Eeuo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEPLOY="$ROOT/deploy"
STEP="start"
OUT_PARTIAL=""
LOCK_FD=9

log() { printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

on_error() {
  rc=$?
  log "FAILED during: $STEP (exit code $rc)"
  if [ -n "$OUT_PARTIAL" ] && [ -d "$OUT_PARTIAL" ]; then rm -rf "$OUT_PARTIAL"; fi
  if [ -n "${BACKUP_DIR:-}" ] && [ -d "${BACKUP_DIR:-}" ]; then date -u +%s > "$BACKUP_DIR/last_failure" 2>/dev/null || true; fi
  exit "$rc"
}
trap on_error ERR

# setting NAME DEFAULT: the environment, else the last NAME=value line of deploy/.env, else DEFAULT.
setting() {
  name=$1
  default=${2-}
  eval "current=\${$name-__unset__}"
  if [ "$current" != "__unset__" ]; then printf '%s' "$current"; return 0; fi
  if [ -r "$DEPLOY/.env" ]; then
    line=$(grep -E "^[[:space:]]*$name=" "$DEPLOY/.env" | tail -n 1 || true)
    if [ -n "$line" ]; then
      value=${line#*=}
      value=${value%%#*}
      value=$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/")
      printf '%s' "$value"
      return 0
    fi
  fi
  printf '%s' "$default"
}

usage() { sed -n '2,12p' "$0"; }

CHECK_ONLY=0
OFFSITE=1
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --no-offsite) OFFSITE=0 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s (try --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

BACKUP_DIR=$(setting BACKUP_DIR /var/backups/securescan)
REMOTE=$(setting BACKUP_REMOTE "")
METHOD=$(setting BACKUP_REMOTE_METHOD "")
SSH_KEY=$(setting BACKUP_SSH_KEY "")
KNOWN_HOSTS=$(setting BACKUP_SSH_KNOWN_HOSTS "")
RECIPIENT=$(setting BACKUP_AGE_RECIPIENT "")
KEY_FILE=$(setting BACKUP_AGE_KEY_FILE "$DEPLOY/secrets/backup_age_key")
INCLUDE_SECRETS=$(setting BACKUP_INCLUDE_SECRETS true)
KEEP_DAYS=$(setting BACKUP_KEEP_DAYS 7)
METRICS_FILE=$(setting BACKUP_METRICS_FILE "")
PROJECT=$(setting BACKUP_PROJECT securescan)
BACKUP_IMAGE=$(setting BACKUP_IMAGE "")

if [ -z "$BACKUP_IMAGE" ] && [ -r "$DEPLOY/images.env" ]; then
  BACKUP_IMAGE=$(grep -E '^IMG_PYTHON=' "$DEPLOY/images.env" | tail -n 1 | cut -d= -f2- || true)
fi
[ -n "$BACKUP_IMAGE" ] || BACKUP_IMAGE="securescan/backend:dev"

if [ -z "$METHOD" ] && [ -n "$REMOTE" ]; then
  case "$REMOTE" in
    /*) METHOD=copy ;;
    *:*) METHOD=rsync ;;
    *) METHOD=copy ;;
  esac
fi

VOL_ARTIFACTS="securescan_artifacts"
VOL_DATA="securescan_data"
VOL_CONTENT="securescan_content"
VOL_MEDIA="${PROJECT}_defectdojo_media"

container_of() {
  docker ps --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$1" --filter status=running -q | head -n 1
}

ssh_command() {
  cmd="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"
  if [ -n "$SSH_KEY" ]; then cmd="$cmd -i $SSH_KEY"; fi
  if [ -n "$KNOWN_HOSTS" ]; then cmd="$cmd -o UserKnownHostsFile=$KNOWN_HOSTS"; fi
  printf '%s' "$cmd"
}

# --------------------------------------------------------------------------------------------- preflight
STEP="preflight"
problems=0
need() { command -v "$1" >/dev/null 2>&1 || { log "missing command: $1"; problems=$((problems + 1)); }; }
for c in docker age sha256sum tar flock date find; do need "$c"; done

if [ -z "$RECIPIENT" ]; then
  if [ -r "$KEY_FILE" ]; then
    need age-keygen
    RECIPIENT=$(age-keygen -y "$KEY_FILE" 2>/dev/null || true)
  fi
fi
case "$RECIPIENT" in
  age1*) : ;;
  *) log "no age recipient: set BACKUP_AGE_RECIPIENT, or create $KEY_FILE with 'age-keygen -o $KEY_FILE'"; problems=$((problems + 1)) ;;
esac
case "$INCLUDE_SECRETS" in true|false) : ;; *) log "BACKUP_INCLUDE_SECRETS must be true or false"; problems=$((problems + 1)) ;; esac
case "$KEEP_DAYS" in ''|*[!0-9]*) log "BACKUP_KEEP_DAYS must be a number"; problems=$((problems + 1)) ;; esac
if [ "$OFFSITE" -eq 1 ]; then
  if [ -z "$REMOTE" ]; then
    log "BACKUP_REMOTE is empty: a backup that stays on this machine is not a backup (use --no-offsite to test locally)"
    problems=$((problems + 1))
  fi
  case "$METHOD" in
    rsync) need rsync; need ssh ;;
    scp) need scp; need ssh ;;
    copy|"") : ;;
    *) log "BACKUP_REMOTE_METHOD must be rsync, scp or copy"; problems=$((problems + 1)) ;;
  esac
fi
if command -v docker >/dev/null 2>&1; then
  docker info >/dev/null 2>&1 || { log "cannot talk to the Docker daemon (run as root or a member of the docker group)"; problems=$((problems + 1)); }
  DB_CONTAINER=$(container_of db || true)
  [ -n "${DB_CONTAINER:-}" ] || { log "the db container of project $PROJECT is not running (start the stack: python3 scripts/dev.py up)"; problems=$((problems + 1)); }
  for v in "$VOL_ARTIFACTS" "$VOL_DATA" "$VOL_CONTENT" "$VOL_MEDIA"; do
    docker volume inspect "$v" >/dev/null 2>&1 || { log "volume $v does not exist"; problems=$((problems + 1)); }
  done
  docker image inspect "$BACKUP_IMAGE" >/dev/null 2>&1 || { log "image $BACKUP_IMAGE is not present locally (python3 scripts/dev.py pull-images)"; problems=$((problems + 1)); }
fi
if [ "$problems" -gt 0 ]; then die "$problems problem(s) found; nothing was backed up"; fi
log "prerequisites ok; backup directory $BACKUP_DIR, project $PROJECT, offsite=$([ "$OFFSITE" -eq 1 ] && echo "$METHOD" || echo no)"
if [ "$CHECK_ONLY" -eq 1 ]; then
  log "--check: nothing was backed up"
  exit 0
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
exec 9>"$BACKUP_DIR/.lock"
flock -n "$LOCK_FD" || die "another backup is running (lock $BACKUP_DIR/.lock)"

# --------------------------------------------------------------------------------------------- the set
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SET="securescan-backup-$STAMP"
OUT_PARTIAL="$BACKUP_DIR/$SET.partial"
OUT="$BACKUP_DIR/$SET"
mkdir -p "$OUT_PARTIAL"
START_EPOCH=$(date -u +%s)

encrypt_to() { age -r "$RECIPIENT" -o "$OUT_PARTIAL/$1"; }

dump_db() {
  STEP="database $1"
  log "dumping database $1"
  docker exec "$DB_CONTAINER" pg_dump --username postgres --format=custom --no-password "$1" | encrypt_to "db-$1.dump.age"
}

# volume_tar VOLUME OUTPUT [tar arguments...]: a read-only, network-less, capability-less container tars the volume.
volume_tar() {
  vol=$1
  out=$2
  shift 2
  STEP="volume $vol"
  log "archiving volume $vol"
  docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true --user 0:0 -v "$vol:/v:ro" --entrypoint tar "$BACKUP_IMAGE" \
    --numeric-owner -C /v "$@" -cf - . | encrypt_to "$out"
}

dump_db securescan
dump_db defectdojo
dump_db sonarqube

STEP="database roles"
log "dumping database roles"
docker exec "$DB_CONTAINER" pg_dumpall --username postgres --globals-only --no-password | encrypt_to "db-globals.sql.age"

# The artifact snapshot comes after the database dumps (design: backup and restore).
volume_tar "$VOL_ARTIFACTS" "artifacts.tar.age"
volume_tar "$VOL_MEDIA" "defectdojo_media.tar.age"
volume_tar "$VOL_DATA" "data.tar.age" --exclude=./workspaces --exclude=./artifacts --exclude=./content --exclude=./backup

STEP="content manifest"
log "listing the content volume"
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH \
  --security-opt no-new-privileges:true --user 0:0 -v "$VOL_CONTENT:/v:ro" --entrypoint sh "$BACKUP_IMAGE" -c '
    cd /v
    echo "# content volume, depth 3 (directories end in /, symbolic links show their target)"
    find . -maxdepth 3 \( -type l -printf "%p -> %l\n" -o -type d -printf "%p/\n" \) | sort
    echo "# contents of lock, manifest and version files"
    find . -maxdepth 3 -type f \( -name "*.lock" -o -name "MANIFEST*" -o -name "VERSION*" \) | sort | while read -r f; do
      echo "## $f"; head -c 65536 "$f"; echo
    done
  ' | encrypt_to "content-manifest.txt.age"

STEP="configuration"
log "archiving the configuration"
config_files=""
for f in .env images.env images.lock.yaml; do
  if [ -f "$DEPLOY/$f" ]; then config_files="$config_files $f"; fi
done
if [ -n "$config_files" ]; then
  # shellcheck disable=SC2086
  tar -C "$DEPLOY" -cf - $config_files | encrypt_to "config.tar.age"
fi

if [ "$INCLUDE_SECRETS" = "true" ]; then
  STEP="secrets"
  log "archiving deploy/secrets (without the age key); the set is encrypted, keep the age private key elsewhere"
  tar -C "$DEPLOY" --exclude=secrets/backup_age_key --exclude=secrets/.gitkeep --exclude=secrets/README.md -cf - secrets | encrypt_to "secrets.tar.age"
fi

# --------------------------------------------------------------------------------------------- manifest
STEP="manifest"
{
  echo "SecureScan backup set $SET"
  echo "created_utc: $STAMP"
  echo "host: $(hostname)"
  echo "project: $PROJECT"
  echo "secrets_included: $INCLUDE_SECRETS"
  echo "release: $(git -C "$ROOT" describe --tags --always 2>/dev/null || echo unknown)"
  echo "age_recipient: $RECIPIENT"
  echo "parts:"
  (cd "$OUT_PARTIAL" && for f in *.age; do printf '  %s %s bytes\n' "$f" "$(stat -c %s "$f")"; done)
} > "$OUT_PARTIAL/MANIFEST.txt"
(cd "$OUT_PARTIAL" && sha256sum ./*.age MANIFEST.txt > SHA256SUMS)
SIZE=$(du -sb "$OUT_PARTIAL" | cut -f1)

# a part of zero bytes means the producing command failed silently
for f in "$OUT_PARTIAL"/*.age; do [ -s "$f" ] || die "part $(basename "$f") is empty"; done
for must in db-securescan.dump.age db-defectdojo.dump.age db-sonarqube.dump.age artifacts.tar.age defectdojo_media.tar.age; do
  [ -s "$OUT_PARTIAL/$must" ] || die "part $must is missing"
done
mv "$OUT_PARTIAL" "$OUT"
OUT_PARTIAL=""
log "set $SET written ($SIZE bytes)"

# --------------------------------------------------------------------------------------------- off the machine
OFFSITE_OK=false
if [ "$OFFSITE" -eq 1 ]; then
  STEP="copy off the machine"
  log "copying to $REMOTE with $METHOD"
  case "$METHOD" in
    rsync)
      rsync -a --partial -e "$(ssh_command)" "$OUT" "${REMOTE%/}/"
      STEP="verify the remote copy"
      remote_host=${REMOTE%%:*}
      remote_path=${REMOTE#*:}
      # shellcheck disable=SC2029
      $(ssh_command) "$remote_host" "cd '${remote_path%/}/$SET' && sha256sum --quiet -c SHA256SUMS"
      ;;
    scp)
      scp -r -q -o BatchMode=yes ${SSH_KEY:+-i "$SSH_KEY"} ${KNOWN_HOSTS:+-o UserKnownHostsFile="$KNOWN_HOSTS"} "$OUT" "${REMOTE%/}/"
      STEP="verify the remote copy"
      remote_host=${REMOTE%%:*}
      remote_path=${REMOTE#*:}
      # shellcheck disable=SC2029
      $(ssh_command) "$remote_host" "cd '${remote_path%/}/$SET' && sha256sum --quiet -c SHA256SUMS"
      ;;
    copy)
      [ -d "$REMOTE" ] || die "BACKUP_REMOTE $REMOTE is not a directory (is the share mounted?)"
      cp -a "$OUT" "${REMOTE%/}/"
      STEP="verify the remote copy"
      (cd "${REMOTE%/}/$SET" && sha256sum --quiet -c SHA256SUMS)
      ;;
  esac
  OFFSITE_OK=true
  log "the copy off the machine is verified"
fi

# --------------------------------------------------------------------------------------------- record success
if [ "$OFFSITE_OK" = "true" ]; then
  STEP="record the success"
  NOW=$(date -u +%s)
  status_json=$(printf '{"last_success": %s, "set": "%s", "size_bytes": %s, "offsite": true, "seconds": %s}\n' \
    "$NOW" "$SET" "$SIZE" "$((NOW - START_EPOCH))")
  printf '%s' "$status_json" > "$BACKUP_DIR/status.json"
  date -u +%s > "$BACKUP_DIR/last_success"
  rm -f "$BACKUP_DIR/last_failure"
  # The worker reads the same file from the data volume and exports securescan_backup_last_success_timestamp.
  worker=$(container_of worker || true)
  if [ -n "$worker" ]; then
    printf '%s' "$status_json" | docker exec -i "$worker" sh -c \
      'mkdir -p /var/lib/securescan/backup && cat > /var/lib/securescan/backup/status.json.tmp && mv /var/lib/securescan/backup/status.json.tmp /var/lib/securescan/backup/status.json' \
      || log "warning: could not record the success in the worker's volume; the backup-age metric will go stale"
  else
    log "warning: the worker container is not running; the backup-age metric will go stale"
  fi
  if [ -n "$METRICS_FILE" ]; then
    {
      echo "# HELP securescan_backup_last_success_timestamp_seconds Unix time of the last verified off-machine backup"
      echo "# TYPE securescan_backup_last_success_timestamp_seconds gauge"
      echo "securescan_backup_last_success_timestamp_seconds $NOW"
      echo "# HELP securescan_backup_last_size_bytes Size of the last backup set"
      echo "# TYPE securescan_backup_last_size_bytes gauge"
      echo "securescan_backup_last_size_bytes $SIZE"
    } > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"
  fi
else
  log "--no-offsite: the success was NOT recorded (the backup-age alert keeps counting)"
fi

# --------------------------------------------------------------------------------------------- retention
STEP="retention"
mapfile -t sets < <(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'securescan-backup-*' ! -name '*.partial' | sort)
total=${#sets[@]}
if [ "$total" -gt 2 ]; then
  for old in "${sets[@]:0:$((total - 2))}"; do
    if [ -n "$(find "$old" -maxdepth 0 -mtime +"$KEEP_DAYS" 2>/dev/null)" ]; then
      log "removing local set $(basename "$old") (older than $KEEP_DAYS days)"
      rm -rf "$old"
    fi
  done
fi
log "done"
