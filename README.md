# SecureScan

On-premises SAST and DAST scanning platform for Sona Comstar. It runs free scanners as on-demand containers, loads every
result into a bundled DefectDojo, keeps a permanent queryable history, and produces SonaComstar-branded reports.
One Ubuntu 24 machine, Docker Compose.

- Design: [docs/design.md](docs/design.md)
- Build plan (milestones M0-M12): [docs/implementation-plan.md](docs/implementation-plan.md)
- Progress: [docs/progress.md](docs/progress.md) - Decisions: [docs/decisions.md](docs/decisions.md)
- Install on the Ubuntu machine: [docs/install.md](docs/install.md) - Security checklist: [docs/security-checklist.md](docs/security-checklist.md)
- Operations: [docs/runbooks/](docs/runbooks/) (stuck scans, DefectDojo, content updates, upgrades, restore drill, rotation, image approvals, performance),
  `scripts/check_host.sh`, `scripts/backup.sh`, `scripts/restore.sh`, alert rules in [deploy/monitoring/alerts.yaml](deploy/monitoring/alerts.yaml)
- Adding or bumping a scanner: [scanners/README.md](scanners/README.md); regression suite: [scanners/regression/README.md](scanners/regression/README.md)

## Quick start (Ubuntu 24)

Prerequisites: Docker Engine 29+ with Compose 2.24+, `uv`, Python 3.14 (via `uv python install 3.14`), Node 24, `openssl`, `git`.
See [deploy/README.md](deploy/README.md) for the host settings.

```
cd backend && uv lock && uv sync && cd ..            # creates uv.lock (commit it)
cd frontend && npm install && cd ..                   # creates package-lock.json (commit it)
python3 -m pip install --user pyyaml                  # for scripts/pin_images.py
python3 scripts/dev.py secrets init
python3 scripts/dev.py certs
python3 scripts/dev.py pin-images
python3 scripts/dev.py up
```

Then open `https://securescan.localtest.me:8443/` (self-signed certificate in development).
