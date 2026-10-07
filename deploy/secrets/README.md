# Secrets

Files in this directory are mounted as Docker secrets. Everything except this README and `.gitkeep` is git-ignored.

`python scripts/dev.py secrets init` creates every secret that can be generated (random values, no trailing newline):
`postgres_superuser_password`, `securescan_db_password`, `defectdojo_db_password`, `sonarqube_db_password`,
`securescan_master_key`, `oidc_client_secret` (empty placeholder until Entra is configured), and from M4:
`dd_admin_password`, `dd_secret_key`, `dd_credential_aes_256_key`, `sonarqube_admin_password`.

`python scripts/dev.py certs` creates `tls/ca.crt`, `tls/server.crt`, `tls/server.key` (self-signed, development only).

Production: replace `tls/server.*` with a certificate from the corporate CA whose subject alternative names cover the portal
host, the DefectDojo host and `db`, and put the CA certificate in `tls/ca.crt`. File permissions: the gateway and the
application read these files as non-root users, so keep them mode 0644 inside a directory only root can list (0700), or use
a vault integration.

Never put a secret on a command line or in an environment variable value; use the `*_FILE` convention.
