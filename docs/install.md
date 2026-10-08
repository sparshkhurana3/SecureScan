# Installing SecureScan on the Ubuntu machine

For the IT administrator who prepares the machine and the security lead who owns the platform. Follow the sections in order; each
ends with a check. Everything here was written before the first run on a real machine, so the first installation is also the test
of this guide: when a step differs from what you see, fix this file in the same change (the deviations belong in `docs/decisions.md`).

Shorthand used in this guide and in `docs/runbooks/`:

```
cd /opt/securescan                       # the checkout of the release you installed
alias sc='docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml'
```

`sc ps`, `sc logs -f worker`, `sc exec db psql -U postgres securescan` then mean what they say. The Compose project is named
`securescan`, so containers are called `securescan-api-1`, `securescan-worker-1`, `securescan-db-1`, and volumes `securescan_artifacts`,
`securescan_pgdata` and so on.

## 1. What you need before you start

| Item | Detail |
| --- | --- |
| Machine | 64-bit Linux with systemd and cgroup v2. Ubuntu 24.04 LTS is the reference. Recommended 16 vCPU, 64 GB RAM, 500 GB SSD; minimum 8 vCPU, 32 GB. Disks of the database and artifact volumes encrypted at rest (design, "Data protection"). |
| Network, outbound HTTPS | github.com, api.github.com, codeload.github.com, objects.githubusercontent.com, raw.githubusercontent.com, login.microsoftonline.com, registry-1.docker.io, auth.docker.io, ghcr.io, quay.io, grype.anchore.io, toolbox-data.anchore.io, services.nvd.nist.gov, www.cisa.gov, dependency-check.github.io, api.pdtm.sh, search.maven.org, repo1.maven.org. `bash scripts/check_host.sh --network` tests them. If the organisation uses a GitHub IP allow list, add the machine's egress address. |
| Network, inbound | One TCP port (443) from the corporate network to the gateway. Nothing from the internet. |
| DNS | Two names under one parent domain, for example `securescan.corp.example` (portal) and `dojo.securescan.corp.example` (DefectDojo). |
| Certificate | From the corporate CA, with subject alternative names for both host names **and** `db` (the same certificate secures the PostgreSQL connections, which are verified with `sslmode=verify-full`). |
| Identity | An Entra ID tenant and someone who may register an application (section 5). |
| GitHub | An owner of the corporate GitHub organisation who may register and install a GitHub App (section 6). |
| People | A named owner for each of the three jobs that cannot be automated (design, "What still needs an owner"). |
| Off-machine backup target | An SSH-reachable host with free space, or a mounted network share (section 11). A machine that is its own only backup is not a backup. |
| NVD API key | Free, from nvd.nist.gov; entered later in Settings. |

## 2. Prepare the machine

### 2.1 Packages and Docker

```
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl python3 python3-yaml age rsync
# Docker Engine and the Compose plugin from Docker's own repository (Engine 29 or later, Compose 2.24 or later)
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Node, Python 3.14 and `uv` are **not** needed on the machine: the backend and the portal are built inside Docker from the lock files
that are committed to the release.

### 2.2 Kernel settings and the host check

```
sudo tee /etc/sysctl.d/99-securescan.conf >/dev/null <<'EOF'
vm.max_map_count=524288
fs.file-max=131072
EOF
sudo sysctl --system
```

Limit and rotate container logs (Docker keeps them forever by default), and ship them to the corporate log pipeline through the
driver your SIEM expects (the audit events are log lines with `event=audit`):

```
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{ "log-driver": "json-file", "log-opts": { "max-size": "50m", "max-file": "5" } }
EOF
sudo systemctl restart docker
```

Then run the host check. It must end with `0 failure(s)`:

```
git clone <the release repository> /opt/securescan && cd /opt/securescan && git checkout <release tag>
bash scripts/check_host.sh --network
```

The worker repeats the checks it can see from inside its container every time it starts. If cgroup v2, `vm.max_map_count` or the Docker
version is wrong it **refuses to start** (`docker logs securescan-worker-1` says which); `SECURESCAN_HOST_CHECK=warn` in `deploy/.env`
only lets you diagnose.

Check: `bash scripts/check_host.sh` prints no `[FAIL]`.

## 3. DNS and certificates

1. Create the two DNS records pointing at the machine.
2. Issue one certificate whose subject alternative names are `securescan.corp.example`, `dojo.securescan.corp.example` and `db`.
3. Put the files in `deploy/secrets/tls/`: `server.crt` (certificate plus intermediates), `server.key`, `ca.crt` (the corporate root and
   intermediate CA that signed it; DefectDojo, SonarQube and SecureScan verify PostgreSQL against it).

```
sudo install -d -m 0700 deploy/secrets deploy/secrets/tls
sudo cp server.crt server.key ca.crt deploy/secrets/tls/ && sudo chmod 0644 deploy/secrets/tls/*
```

The secret files must be readable by the non-root users inside the containers, so the files are 0644 inside a directory only root can
list (`deploy/secrets` is 0700). Never use `python3 scripts/dev.py certs` here: it makes a development certificate.

## 4. Configure `deploy/.env`

```
cp deploy/.env.example deploy/.env
```

Set at least (values are examples; no value in this file is a secret):

```
SECURESCAN_PORT=443
SECURESCAN_PUBLIC_URL=https://securescan.corp.example
SECURESCAN_DEFECTDOJO_PUBLIC_URL=https://dojo.securescan.corp.example
SECURESCAN_COOKIE_DOMAIN=securescan.corp.example      # the portal host: the DefectDojo host below it sees the session
DD_HOST=dojo.securescan.corp.example
SECURESCAN_OIDC_ISSUER=https://login.microsoftonline.com/<tenant id>/v2.0
SECURESCAN_OIDC_CLIENT_ID=<application (client) id>

# Run the Docker socket proxy as nobody in the socket's group instead of root:
SOCKET_PROXY_USER=65534:<gid>                          # <gid> from: stat -c %g /var/run/docker.sock

# Backups (section 11); see the header of scripts/backup.sh for every setting
BACKUP_DIR=/var/backups/securescan
BACKUP_REMOTE=backup@backuphost:/srv/securescan        # or a mounted directory, e.g. /mnt/backup/securescan
BACKUP_SSH_KEY=/root/.ssh/securescan_backup
```

`SECURESCAN_PUBLIC_URL` without a port means 443. In production leave `SECURESCAN_HOST_CHECK` unset.

## 5. Register SecureScan in Microsoft Entra ID

Done by an Entra administrator (`deploy/README.md` holds the short form).

1. Entra admin centre -> Applications -> App registrations -> New registration. Name `SecureScan`, single tenant, platform **Web**, redirect URI
   `https://securescan.corp.example/api/v1/auth/callback`.
2. Overview: copy the *Application (client) ID* and the *Directory (tenant) ID* into `SECURESCAN_OIDC_CLIENT_ID` and the issuer URL above.
3. Certificates and secrets -> New client secret (choose the longest lifetime your policy allows; the expiry date goes in your calendar and
   in `docs/runbooks/credential-rotation.md`). Copy the **value** once:
   `printf '%s' '<value>' | sudo tee deploy/secrets/oidc_client_secret >/dev/null && sudo chmod 0644 deploy/secrets/oidc_client_secret`
4. App roles -> Create app role, twice: display name `Admin`, value `Admin`, allowed member types *Users/Groups*; display name `Analyst`,
   value `Analyst`, same type. The values are case-sensitive: the portal reads them from the `roles` claim.
5. Enterprise applications -> SecureScan -> Properties -> **Assignment required = Yes**.
6. Enterprise applications -> SecureScan -> Users and groups -> Add user/group: assign the security administrators' group to `Admin` and the
   analysts' group to `Analyst`.

Check, after the first start: a user in the Admin group signs in and sees Settings; an Analyst does not; a user assigned to neither is
refused by Entra before they reach SecureScan; a user assigned without a role is refused by SecureScan with "no role" (and an
`auth.login_denied` audit event).

## 6. Register the GitHub App

Done by an owner of the corporate GitHub organisation. No webhook, nothing inbound.

1. Organisation -> Settings -> Developer settings -> GitHub Apps -> New GitHub App. Name `SecureScan <company>`, homepage URL = the portal URL.
2. **Webhook: untick Active.**
3. Repository permissions: **Contents: Read-only** and **Metadata: Read-only**. Nothing else (permission changes later need the organisation
   owner's re-approval).
4. Where can this app be installed: *Only on this account*. Create the App.
5. Note the *App ID* and *Client ID*. Generate a private key (a `.pem` downloads).
6. Install App -> choose the repositories (all, or a selection). The number at the end of the installation URL
   (`.../settings/installations/<number>`) is the *installation ID*.
7. Give SecureScan the key and the numbers either in the portal (Settings -> GitHub connection; the key is stored encrypted) or as a file:
   `sudo install -m 0644 key.pem deploy/secrets/github_app_key_1` (a second key as `github_app_key_2` allows rotation without downtime,
   `docs/runbooks/github-app-key-rotation.md`). Then press Test in Settings.

The Compose file does not mount `github_app_key_*` by default; to use files, add the secret entries and the
`SECURESCAN_GITHUB_APP_KEY_1_FILE` variable to the `worker` service (see `docs/build-notes/M7.md`), or simply use the portal.

## 7. Secrets

```
python3 scripts/dev.py secrets init          # creates every secret that can be generated; keeps existing files
age-keygen -o deploy/secrets/backup_age_key  # the backup key pair; the public key is printed
```

`age-keygen` prints `Public key: age1...`. **Copy `deploy/secrets/backup_age_key` (the private key) to a vault or a sealed envelope that is not
this machine, and keep it there.** Without it no backup can be read; with only the backup, nobody can restore. The file stays on the
machine because `scripts/backup.sh` derives the public key from it; you may instead keep only the public key on the machine
(`BACKUP_AGE_RECIPIENT=age1...` in `deploy/.env`) and delete the file once it is stored safely.

Also keep copies of `deploy/secrets/securescan_master_key` and `dd_admin_password` (the DefectDojo break-glass password) in the vault: the
backup contains them too (encrypted), but a restore on a new machine needs them only after the age key. `docs/security-checklist.md` lists every secret and where it lives.

## 8. Images

```
python3 scripts/dev.py pin-images            # resolves every tag in deploy/images.lock.yaml to a digest, writes deploy/images.env
python3 scripts/dev.py pull-images           # pulls every pinned image (the worker may not pull: the socket proxy forbids it)
```

The self-built SpotBugs image (`securescan/spotbugs-fsb`) is built from `scanners/spotbugs/Dockerfile` (see `scanners/spotbugs/README.md`) and
stays on this machine. Commit `deploy/images.lock.yaml` with its digests so the release records exactly what it ran.

## 8a. Vendor the upstream DefectDojo Compose file

`deploy/defectdojo/upstream/docker-compose.yml` in a fresh checkout is a placeholder written without network access. Replace it with the verbatim
file of the DefectDojo release before the first start, then check that our override still applies:

```
curl -fsSL https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/3.4.0/docker-compose.yml -o deploy/defectdojo/upstream/docker-compose.yml
docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml config > /dev/null
```

If `config` fails on `!reset`, `!override` or a service name in `deploy/defectdojo/override.yaml`, adjust the override to the real file. If Compose refuses
the nested `include`, list both files with `-f` in `scripts/dev.py` (`compose_base`) and note it in `docs/decisions.md`. Commit the real file.

## 9. First start

```
python3 scripts/dev.py up                    # builds the backend and gateway images, starts the stack
sc ps                                        # wait until db, api, worker, gateway are healthy and dojo-init has exited
sc logs -f dojo-init                         # "nothing to change" or the list of what it set up
```

DefectDojo needs a few minutes on its first start (database migration). Expected always-on containers: `gateway`, `api`, `worker`, `db`,
`socket-proxy`, DefectDojo's `nginx`, `uwsgi`, `celerybeat`, `celeryworker`, `valkey`. No scanner, SonarQube server or proxy runs until a job needs it.

### Smoke test (30 minutes)

1. Open `https://securescan.corp.example/`, sign in as an Admin. Settings -> System health shows no red item.
2. Settings -> GitHub connection: enter the App values, press Test, press Discover; repositories appear.
3. Enter the NVD API key in Settings (credentials) and let the first updates run: Grype's database at 07:30 UTC, the NVD data at 03:00 UTC (the first NVD download takes 20 minutes or more; Dependency-Check scans wait for it). The scanner health page shows the age of every feed.
4. SAST scan -> register an application "smoke-test" (internal), a version `main`, a zip target: upload `backend/tests/fixtures/sample-apps/python-planted` zipped
   (`cd backend/tests/fixtures/sample-apps && zip -r /tmp/python-planted.zip python-planted`). Start a scan with the `code-standard` profile.
5. Watch the live log. Each job ends `imported`; the scan detail shows findings; open the report and download the PDF (it carries your name as a watermark).
6. Historical data: filter by the application, export CSV, open it in a text editor: cells starting with `=` are prefixed with `'`.
7. Open DefectDojo through the portal button; the product "smoke-test" holds the findings. `https://dojo.securescan.corp.example/` in a private window without the portal session redirects to the portal login.
8. `docker ps` shows no scanner container afterwards; `sc exec worker python -m securescan.domain.regression check` reads the regression expectations.
9. Take the first backup (section 11) and look at its `MANIFEST.txt`.

## 10. Monitoring

Logs are JSON on stdout of every container. Metrics are served by the api (`/metrics`, port 8000) and the worker (port 9100); neither port is
published. To let the corporate Prometheus scrape them from the same host create `deploy/compose.override.yaml` (not committed):

```
services:
  api:    { ports: ["127.0.0.1:18000:8000"] }
  worker: { ports: ["127.0.0.1:19100:9100"] }
```

and start with `-f deploy/compose.override.yaml` in the alias, or run a Prometheus (or an exporter agent) container on the `securescan_backend` network.
Copy `deploy/monitoring/alerts.yaml` into Prometheus's rule files (`promtool check rules` first). Each alert names its runbook.

## 11. Backups

Targets (design): recovery point 24 hours, recovery time 4 hours, from copies held off the machine.

```
bash scripts/backup.sh --check               # prerequisites and settings; changes nothing
bash scripts/backup.sh                       # a first full backup, copied off the machine and verified
```

Test the SSH target first: the user in `BACKUP_REMOTE` must log in with `BACKUP_SSH_KEY` without a prompt, and the host key must be in
`known_hosts` (`ssh -i <key> backup@backuphost true`). Schedule it from the host's cron after the quiet period:

```
echo '30 1 * * *  root  cd /opt/securescan && bash scripts/backup.sh >> /var/log/securescan-backup.log 2>&1' | sudo tee /etc/cron.d/securescan-backup
```

Rotate `/var/log/securescan-backup.log` with logrotate. A success updates the metric `securescan_backup_last_success_timestamp`; the alert
`SecureScanBackupOld` fires after 26 hours without one. **Run the restore drill (`docs/runbooks/restore.md`) before go-live and every quarter.**

## 12. Upgrade windows

Nothing changes silently: every image is pinned by digest and every update waits for a person.

| Cadence | Task | Who | Runbook |
| --- | --- | --- | --- |
| Daily, automatic | Grype and NVD databases, GitHub poll, triage state refresh | the platform | `docs/runbooks/content-update-failed.md` when an alert fires |
| Weekly, automatic | Semgrep rules and Nuclei templates, behind the regression check | the platform | `docs/runbooks/content-update-failed.md` |
| Monthly | Review and approve proposed scanner images (`GET /api/v1/image-versions`; the Settings page for it is listed in `docs/build-notes/M11.md`); review alerts, the import queue and the DefectDojo accounts | security team | `docs/runbooks/approving-image-digest.md` |
| Quarterly | SecureScan and DefectDojo releases, OS and Docker patches, the **restore drill** | IT team | `release-upgrade.md`, `defectdojo-upgrade.md`, `sonarqube-upgrade.md`, `restore.md` |
| Yearly | Rule packs, profiles, verdict policy, role assignments, licence terms, the pinned GitHub API version, the Entra client secret and GitHub App key | security team | `credential-rotation.md`, `github-app-key-rotation.md` |
| Every 3 to 4 years | Python, PostgreSQL and Node build versions | code owner | `release-upgrade.md` |

Announce a maintenance window before a release upgrade: scans in progress are finished or cancelled first (`docs/runbooks/release-upgrade.md`).

## 13. Day-2 pointers

- Stuck scan, orphaned container: `docs/runbooks/stuck-scan.md`. DefectDojo not reachable or rejecting imports: `docs/runbooks/defectdojo-unreachable.md`.
- Break-glass: DefectDojo `admin` (password `deploy/secrets/dd_admin_password`) and the SonarQube admin (`sonarqube_admin_password`). Every use raises an alert; write down who used it and why.
- Performance and growth: `docs/runbooks/performance.md`. History, reports and raw reports are kept forever; plan disk growth accordingly.
- Hardening and what was verified: `docs/security-checklist.md`.
