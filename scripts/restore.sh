#!/usr/bin/env bash
# Restores a SecureScan backup set (made by scripts/backup.sh) onto a fresh machine or a clean Compose project.
#
#   bash scripts/restore.sh SET_DIR --identity AGE_KEY_FILE            # full restore, asks you to confirm
#   bash scripts/restore.sh SET_DIR --identity AGE_KEY_FILE --check    # verify checksums and decrypt every part, change nothing
#   bash scripts/restore.sh --help
#
# SET_DIR is a directory like securescan-backup-20261007T013000Z (copied back from the off-machine target).
# AGE_KEY_FILE is the age PRIVATE key that belongs to the recipient the backups were encrypted for. It is read by
# `age` and never copied anywhere. Options:
#   --project NAME        Compose project name (default securescan)
#   --yes                 do not ask for confirmation (for the restore drill in a script)
#   --keep-secrets        keep deploy/secrets and deploy/.env as they are even if the set holds them
#   --no-start            restore, but leave the stack stopped (default: start it and wait for the api)
#   --skip-volumes        restore only the databases and the secrets (artifacts and media stay empty)
#
# Order of work (docs/runbooks/restore.md is the drill around it):
#   1. verify SHA256SUMS and test-decrypt every part
#   2. put deploy/secrets and the configuration back (only when they are absent: a fresh machine has none)
#   3. create the Compose project without starting it (volumes, networks, containers)
#   4. start the db container alone (its init script creates the three roles and databases from the restored secrets)
#   5. pg_restore each database; untar the volumes
#   6. start the whole stack (the migrate container brings the schema to the head of THIS release)
# Prerequisites on the machine: scripts/check_host.sh passes, Docker and age are installed, the repository is checked out
# at the release the backup came from (or newer), and the images are present (python3 scripts/dev.py pull-images).
set -Eeuo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEPLOY="$ROOT/deploy"
STEP="start"

log() { printf '%s restore: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }
trap 'rc=$?; log "FAILED during: $STEP (exit code $rc). Read the messages above, fix the cause, remove the half-restored project (python3 scripts/dev.py down --volumes) and run again."; exit "$rc"' ERR

usage() { sed -n '2,13p' "$0"; }

SET_DIR=""
IDENTITY=""
PROJECT=securescan
ASSUME_YES=0
CHECK_ONLY=0
KEEP_SECRETS=0
START_STACK=1
SKIP_VOLUMES=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --identity) [ "$#" -ge 2 ] || die "--identity needs a file"; IDENTITY=$2; shift 2 ;;
    --project) [ "$#" -ge 2 ] || die "--project needs a name"; PROJECT=$2; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    --keep-secrets) KEEP_SECRETS=1; shift ;;
    --no-start) START_STACK=0; shift ;;
    --skip-volumes) SKIP_VOLUMES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) printf 'unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    *) [ -z "$SET_DIR" ] || die "only one backup set can be restored"; SET_DIR=$1; shift ;;
  esac
done

[ -n "$SET_DIR" ] || { usage; exit 2; }
[ -d "$SET_DIR" ] || die "$SET_DIR is not a directory"
[ -n "$IDENTITY" ] || die "give the age private key with --identity FILE"
[ -r "$IDENTITY" ] || die "cannot read the identity file $IDENTITY"
SET_DIR=$(cd "$SET_DIR" && pwd)
SET_NAME=$(basename "$SET_DIR")

for c in age sha256sum tar; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
if [ "$CHECK_ONLY" -eq 0 ]; then
  for c in docker; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
fi

# An image that has tar and sh: the pinned Python image of deploy/images.env, else the locally built backend image.
TOOL_IMAGE=$(grep -E '^IMG_PYTHON=' "$DEPLOY/images.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)
[ -n "$TOOL_IMAGE" ] || TOOL_IMAGE=securescan/backend:dev

# decrypt PART: the plain content on stdout
decrypt() { age -d -i "$IDENTITY" "$SET_DIR/$1"; }

# --------------------------------------------------------------------------------------------- 1. verify
STEP="verify the checksums"
[ -f "$SET_DIR/SHA256SUMS" ] || die "SHA256SUMS is missing in $SET_DIR"
(cd "$SET_DIR" && sha256sum --quiet -c SHA256SUMS) || die "checksum mismatch: the set is damaged or incomplete; fetch it again"
log "checksums ok for $SET_NAME"
for must in db-securescan.dump.age db-defectdojo.dump.age artifacts.tar.age defectdojo_media.tar.age; do
  [ -f "$SET_DIR/$must" ] || die "part $must is missing from the set"
done

STEP="test-decrypt every part"
for part in "$SET_DIR"/*.age; do
  name=$(basename "$part")
  if decrypt "$name" > /dev/null; then
    log "decrypts: $name ($(stat -c %s "$part") bytes)"
  else
    die "cannot decrypt $name with $IDENTITY (wrong key?)"
  fi
done
if [ "$CHECK_ONLY" -eq 1 ]; then
  log "--check: the set is complete and every part decrypts; nothing was restored"
  exit 0
fi

# --------------------------------------------------------------------------------------------- confirm
STEP="confirm"
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"
existing=$(docker ps -a --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' | wc -l)
if [ "$existing" -gt 0 ]; then
  die "the Compose project $PROJECT already has $existing container(s). Restore onto a clean project: python3 scripts/dev.py down --volumes (this deletes its data), then run this again."
fi
if docker volume inspect securescan_pgdata >/dev/null 2>&1; then
  has_cluster=$(docker run --rm --network none -v securescan_pgdata:/v:ro --entrypoint sh "$TOOL_IMAGE" -c 'find /v -maxdepth 3 -name PG_VERSION | head -n 1' 2>/dev/null || true)
  [ -z "$has_cluster" ] || die "the volume securescan_pgdata already holds a PostgreSQL cluster. Remove it first (python3 scripts/dev.py down --volumes) or restore on another machine."
fi
if [ "$ASSUME_YES" -ne 1 ]; then
  [ -t 0 ] || die "not a terminal: pass --yes to confirm the restore"
  printf 'This restores %s into project "%s" on this machine (databases, volumes, secrets). Type the project name to continue: ' "$SET_NAME" "$PROJECT"
  read -r answer
  [ "$answer" = "$PROJECT" ] || die "not confirmed"
fi

# --------------------------------------------------------------------------------------------- 2. secrets and configuration
compose() {
  if [ -f "$DEPLOY/images.env" ]; then
    docker compose -p "$PROJECT" --project-directory "$DEPLOY" --env-file "$DEPLOY/.env" --env-file "$DEPLOY/images.env" -f "$DEPLOY/compose.yaml" "$@"
  else
    docker compose -p "$PROJECT" --project-directory "$DEPLOY" --env-file "$DEPLOY/.env" -f "$DEPLOY/compose.yaml" "$@"
  fi
}

STEP="configuration and secrets"
mkdir -p "$DEPLOY"
if [ "$KEEP_SECRETS" -eq 0 ]; then
  if [ -f "$SET_DIR/config.tar.age" ]; then
    if [ -f "$DEPLOY/.env" ]; then
      log "deploy/.env exists: keeping the configuration already here (the set's copy stays in the set)"
    else
      log "restoring deploy/.env, images.env and images.lock.yaml"
      decrypt config.tar.age | tar -C "$DEPLOY" --no-same-owner -xf -
    fi
  fi
  if [ -f "$SET_DIR/secrets.tar.age" ]; then
    if [ -f "$DEPLOY/secrets/securescan_master_key" ]; then
      log "deploy/secrets already holds a master key: keeping the secrets already here"
    else
      log "restoring deploy/secrets"
      decrypt secrets.tar.age | tar -C "$DEPLOY" --no-same-owner -xf -
    fi
  else
    [ -f "$DEPLOY/secrets/securescan_master_key" ] || die "the set holds no secrets and deploy/secrets has no securescan_master_key: copy the secrets from their vault into deploy/secrets first, then run again with --keep-secrets"
  fi
fi
[ -f "$DEPLOY/.env" ] || die "deploy/.env is missing (copy deploy/.env.example and fill it in)"
[ -f "$DEPLOY/secrets/securescan_master_key" ] || die "deploy/secrets/securescan_master_key is missing; without the master key the stored credentials cannot be read"
[ -f "$DEPLOY/images.env" ] || die "deploy/images.env is missing: run python3 scripts/dev.py pin-images"
# images.env may only exist now (restored from the set): look for the helper image again
TOOL_IMAGE=$(grep -E '^IMG_PYTHON=' "$DEPLOY/images.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)
[ -n "$TOOL_IMAGE" ] || TOOL_IMAGE=securescan/backend:dev

# --------------------------------------------------------------------------------------------- 3. project, 4. db
STEP="create the Compose project"
log "creating the project without starting it"
compose up --no-start
STEP="start the database"
log "starting the db container"
compose up -d db
db_container=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=db" -q | head -n 1)
[ -n "$db_container" ] || die "the db container did not start"
health=unknown
for _ in $(seq 1 60); do
  health=$(docker inspect -f '{{.State.Health.Status}}' "$db_container" 2>/dev/null || echo unknown)
  if [ "$health" = "healthy" ]; then break; fi
  sleep 5
done
[ "$health" = "healthy" ] || die "the db container did not become healthy within 5 minutes (docker logs $db_container)"
for name in securescan defectdojo; do
  docker exec "$db_container" psql --username postgres --no-password -tAc "select 1 from pg_database where datname = '$name'" | grep -q 1 \
    || die "the database $name was not created by the init script (it runs only on an empty data directory)"
done

# --------------------------------------------------------------------------------------------- 5. databases and volumes
for name in securescan defectdojo; do
  STEP="restore database $name"
  log "restoring database $name"
  decrypt "db-$name.dump.age" | docker exec -i "$db_container" pg_restore --username postgres --dbname "$name" \
    --exit-on-error --single-transaction --clean --if-exists --no-password
done

restore_volume() {
  # restore_volume VOLUME PART
  vol=$1
  part=$2
  STEP="restore volume $vol"
  [ -f "$SET_DIR/$part" ] || { log "no $part in the set; volume $vol stays empty"; return 0; }
  docker volume inspect "$vol" >/dev/null 2>&1 || die "volume $vol was not created by the Compose project"
  log "restoring volume $vol from $part"
  decrypt "$part" | docker run --rm -i --network none --read-only --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --security-opt no-new-privileges:true --user 0:0 \
    -v "$vol:/v" --entrypoint tar "$TOOL_IMAGE" --numeric-owner -C /v -xf -
}

if [ "$SKIP_VOLUMES" -eq 0 ]; then
  restore_volume securescan_artifacts artifacts.tar.age
  restore_volume "${PROJECT}_defectdojo_media" defectdojo_media.tar.age
  restore_volume securescan_data data.tar.age
fi

# --------------------------------------------------------------------------------------------- 6. start
if [ "$START_STACK" -eq 1 ]; then
  STEP="start the stack"
  log "starting the whole stack"
  compose up -d
  api_container=""
  health=unknown
  for _ in $(seq 1 60); do
    api_container=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=api" -q | head -n 1)
    if [ -n "$api_container" ]; then
      health=$(docker inspect -f '{{.State.Health.Status}}' "$api_container" 2>/dev/null || echo unknown)
      if [ "$health" = "healthy" ]; then break; fi
    fi
    sleep 10
  done
  [ "$health" = "healthy" ] || die "the api did not become healthy within 10 minutes (docker logs securescan-api-1)"
  log "the api is healthy"
fi

log "restore finished. Now:"
log "  1. open the portal, sign in, open a report that existed before the backup (Historical data -> a scan -> its report)"
log "  2. open DefectDojo through the portal and check the products and findings are there"
log "  3. Settings -> System health: no red items; python3 scripts/dev.py logs worker shows jobs being picked up"
log "  4. take a new backup (bash scripts/backup.sh) and record the drill time in docs/runbooks/restore.md"
