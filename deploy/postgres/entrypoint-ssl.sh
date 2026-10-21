#!/bin/sh
# Copies the TLS key pair from Docker secrets to a path owned by postgres with the permissions
# PostgreSQL insists on, then starts the stock entrypoint with ssl enabled.
set -eu
install -d -o postgres -g postgres -m 0700 /var/lib/pg-tls
install -o postgres -g postgres -m 0644 /run/secrets/pg_server_cert /var/lib/pg-tls/server.crt
install -o postgres -g postgres -m 0600 /run/secrets/pg_server_key /var/lib/pg-tls/server.key
# Memory settings for the 4 vCPU / 8 GB machine; the container's limit is 1 GB (compose.yaml).
exec docker-entrypoint.sh postgres \
  -c shared_buffers=256MB \
  -c effective_cache_size=768MB \
  -c work_mem=4MB \
  -c maintenance_work_mem=64MB \
  -c max_connections=100 \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/pg-tls/server.crt \
  -c ssl_key_file=/var/lib/pg-tls/server.key \
  -c ssl_min_protocol_version=TLSv1.2
