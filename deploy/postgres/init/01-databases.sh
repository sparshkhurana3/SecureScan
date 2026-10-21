#!/bin/sh
# Runs once, on an empty data directory. Creates one database and one role per product.
set -eu

create() {
  role="$1"; db="$2"; pw_file="$3"
  pw="$(tr -d '\r\n' < "$pw_file")"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE ${role} LOGIN PASSWORD '${pw}';
CREATE DATABASE ${db} OWNER ${role} ENCODING 'UTF8';
SQL
}

create securescan securescan /run/secrets/securescan_db_password
create defectdojo defectdojo /run/secrets/defectdojo_db_password
