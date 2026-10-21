# Deployment notes

Full installation guide: `docs/install.md` (written in M11). This file holds what M0-M2 need.

## Host prerequisites (Ubuntu 24.04)

- Docker Engine 29 or later and Docker Compose 2.24 or later (repeated `--env-file` and the `include` element).
- cgroup v2 (the Ubuntu 24.04 default) so container CPU, memory and PID limits are enforced.
- Outbound HTTPS to the hosts listed in `docs/implementation-plan.md` section 2.4.
- DNS names for the portal and DefectDojo under one parent domain, and a TLS certificate whose subject alternative names
  cover both hosts and `db`.
- Machine: 4 vCPU, 8 GB RAM, 500 GB SSD. Scans run one at a time (docs/decisions.md, 2026-10-21).

## First start

```
python3 scripts/dev.py secrets init
python3 scripts/dev.py certs          # development only
python3 scripts/dev.py pin-images     # fills deploy/images.lock.yaml and deploy/images.env
python3 scripts/dev.py up
```

`dev.py` runs Compose as `docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env`.
The project name is fixed to `securescan`, so containers are named `securescan-db-1`, `securescan-api-1` and so on.

## Entra ID setup (for IT; finalised after spike S4)

1. Register an application in Microsoft Entra ID; redirect URI `https://<portal host>/api/v1/auth/callback`.
2. Add two app roles with values `Admin` and `Analyst` (allowed member types: users and groups).
3. On the enterprise application set "Assignment required" to yes and assign the security groups to the roles.
4. Create a client secret (or certificate) and put it in `deploy/secrets/oidc_client_secret`; set
   `SECURESCAN_OIDC_ISSUER` (`https://login.microsoftonline.com/<tenant id>/v2.0`) and `SECURESCAN_OIDC_CLIENT_ID` in `deploy/.env`.
