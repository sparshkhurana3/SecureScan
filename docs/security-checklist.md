# Security checklist

Plan section 5.1, one line per control, each with the command or screen that verifies it. Written at M11 **before the first run on a real
machine**: nothing below is ticked, because nothing has been verified. The person who installs the platform walks the list once at go-live
(tick the box, write the date and your initials next to it) and again after every release upgrade and every Docker upgrade.

Shorthand (as in `docs/install.md`): `sc` is `docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml`;
`$PORTAL` is the portal address, `$DOJO` the DefectDojo address, `psql` below is
`sc exec -T db psql -U postgres -d securescan -c` (add `-d defectdojo` for DefectDojo's database).

## 1. Identity, sessions and roles

- [ ] **Sign-in only through Entra ID; assignment required.** Entra admin centre -> Enterprise applications -> SecureScan -> Properties: *Assignment required* = Yes.
  A user who is not assigned cannot reach SecureScan (Entra refuses). SecureScan has no password form: `curl -sk $PORTAL/api/v1/auth/login -o /dev/null -w '%{http_code}\n'` redirects (302) to `login.microsoftonline.com`.
- [ ] **Roles come from the `roles` claim; no role means no access.** Sign in as a user assigned without a role: the portal answers "no role"; Settings -> Audit log shows `auth.login_denied`.
  `psql "select role, count(*) from users group by role"` lists only `Admin` and `Analyst`. There is no table of local passwords.
- [ ] **Two roles, enforced on the server.** As an Analyst open `$PORTAL/api/v1/image-versions` (and Settings in the portal): 403. As an Admin: 200.
- [ ] **Server-side sessions.** `psql "select count(*), bool_and(length(token_hash) = 64) from sessions"` -> the table stores only SHA-256 hashes of the tokens.
- [ ] **Cookies `HttpOnly; Secure; SameSite=Lax`.** Browser developer tools -> Application -> Cookies: `securescan_session` has HttpOnly, Secure and SameSite=Lax; its domain is the parent host name.
- [ ] **CSRF on every state-changing request.** `curl -sk -X POST -b "securescan_session=<value from your browser>" -H 'content-type: application/json' -d '{}' $PORTAL/api/v1/applications -w '%{http_code}\n'` -> 403 (no `X-CSRF-Token` header).
- [ ] **Per-session rate limit at the gateway.** `grep -n limit_req deploy/gateway/nginx.conf` shows `rate=20r/s burst=40`;
  `for i in $(seq 1 300); do curl -sk -o /dev/null -w '%{http_code}\n' -b 'securescan_session=x' $PORTAL/api/v1/auth/check; done | sort | uniq -c` shows 503 for the excess (nginx's default for `limit_req`).
- [ ] **Session lifetime.** Idle 8 hours, absolute 24 hours (`SECURESCAN_SESSION_IDLE_HOURS`, `SECURESCAN_SESSION_MAX_HOURS`): `sc exec -T api printenv | grep SESSION` shows no weaker override.

## 2. DefectDojo access

- [ ] **Reachable only through the gateway with `auth_request`.** In a private browser window open `$DOJO`: redirect to the portal login. `docker ps --format '{{.Names}}  {{.Ports}}'` shows a published port **only** for the gateway;
  from another machine `nc -zv <machine> 8080` fails. `docker network inspect securescan_dojo --format '{{.Internal}}'` -> `true`.
- [ ] **Accounts are provisioned, not created by hand.** Sign in to the portal once as a new Analyst; Settings -> DefectDojo accounts lists the account with the initial password shown once. `defectdojo_account.create` is in the audit log.
- [ ] **90-day inactivity disable.** Settings -> DefectDojo accounts shows the "last login" and "disabled" columns; the setting `SECURESCAN_DEFECTDOJO_ACCOUNT_EXPIRY_DAYS` is 90 (`sc exec -T api python -c "from securescan.config import get_settings; print(get_settings().defectdojo_account_expiry_days)"`).
- [ ] **Break-glass credentials sealed and their use alerted.** `deploy/secrets/dd_admin_password` exists and a copy sits in the vault. Test: sign in to DefectDojo as `admin` through the gateway; after the next run of `account_expiry` (04:00 UTC) the audit log has `defectdojo.break_glass_login` and Prometheus shows `securescan_break_glass_logins_total{tool="defectdojo"}` up by one; the alert `SecureScanBreakGlassLogin` fires (`deploy/monitoring/alerts.yaml`).

## 3. Scanner containers

- [ ] **Fixed catalogue; containers are built only from it.** `git log --oneline -- scanners/catalogue.yaml` shows reviewed changes only; `sc exec -T worker python -c "from securescan.runner.catalogue import load_catalogue; print(sorted(load_catalogue()))"` lists the tools. There is no tool outside the catalogue and no CodeQL.
- [ ] **No network for code scanners; DAST only through its proxy.** While a scan runs:
  `docker inspect --format '{{.Name}} net={{.HostConfig.NetworkMode}}' $(docker ps -q --filter name=securescan-job)` -> `net=none` for Semgrep, Gitleaks, Syft, Grype, SpotBugs.
- [ ] **Read-only rootfs, dropped capabilities, no-new-privileges, uid, PID and memory limits, hard timeout.** Same containers:
  `docker inspect --format '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} sec={{.HostConfig.SecurityOpt}} user={{.Config.User}} pids={{.HostConfig.PidsLimit}} mem={{.HostConfig.Memory}}' <id>` -> `ro=true capdrop=[ALL] sec=[no-new-privileges:true]`, a numeric user, non-zero pids and memory.
  A job that exceeds its timeout ends `timed_out` with its container removed (`docker ps -a --filter name=securescan-job` shows none left).
- [ ] **No secret in a scanner container's command line or environment.** `docker inspect --format '{{.Config.Cmd}} {{.Config.Env}}' <id>`: no token, no key; only the one credential a job needs, and only for that job.
- [ ] **Workspace removed afterwards.** `sudo ls /var/lib/docker/volumes/securescan_data/_data/workspaces` is empty when no scan runs (the hourly `workspace_gc` removes leftovers older than 24 hours).

## 4. The Docker socket proxy

- [ ] **The proxy is the only container with the Docker socket; the worker is its only client.** `docker ps -q | xargs docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' | grep docker.sock` -> only `securescan-socket-proxy-1`;
  `docker network inspect securescan_docker --format '{{range .Containers}}{{.Name}} {{end}}'` -> the proxy and the worker (plus a scanner container never joins it).
- [ ] **The allowlist is exactly `deploy/socket-proxy/args.env`, and anything else is refused.** Run the snippet below; each line must print 403. Re-run `spikes/s2/run.sh enforce` after every change of `args.env` (also after M9's DAST work).

```
sc exec -T worker python - <<'PY'
import urllib.request as u, urllib.error as e
for method, path in (("POST", "/v1.44/images/create?fromImage=alpine"), ("GET", "/v1.44/info"), ("POST", "/v1.44/containers/abc/exec")):
    try:
        u.urlopen(u.Request("http://socket-proxy:2375" + path, method=method, data=b"" if method == "POST" else None))
        print(method, path, "ALLOWED")
    except e.HTTPError as x:
        print(method, path, x.code)
PY
```

- [ ] **Bind mounts are restricted to the data and content volumes; no image pulls through the proxy.** `grep ALLOWBINDMOUNTFROM deploy/socket-proxy/args.env` lists only the two volume paths (the daemon's real Mountpoints); the proxy answers 403 to `images/create`
  (above); images arrive by `python3 scripts/dev.py pull-images`.
- [ ] **The proxy itself runs unprivileged.** `docker inspect securescan-socket-proxy-1 --format 'ro={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}} capdrop={{.HostConfig.CapDrop}}'` -> `ro=true`, `capdrop=[ALL]`, and with `SOCKET_PROXY_USER` set a non-root user.

## 5. Hardening of the always-on set

- [ ] **Run the inspection for every container of the project:**
  `for c in $(sc ps -q); do docker inspect --format '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} sec={{.HostConfig.SecurityOpt}} user={{.Config.User}} pids={{.HostConfig.PidsLimit}} mem={{.HostConfig.Memory}}' $c; done`

| Service | Expected | Why the exception |
| --- | --- | --- |
| api, worker, migrate, dojo-init, gateway, socket-proxy | `ro=true`, `capdrop=[ALL]`, `sec=[no-new-privileges:true]`, memory and pids limits | none |
| db (PostgreSQL) | `ro=false`, `capdrop=[ALL]`, `capadd=[CHOWN DAC_OVERRIDE FOWNER SETGID SETUID]`, `no-new-privileges` | the official image's entrypoint runs as root, chowns the data and TLS directories and then drops to `postgres` |
| DefectDojo nginx, uwsgi, celerybeat, celeryworker, initializer, valkey | `ro=false` unless the hardening snippet of `docs/build-notes/M11.md` was applied to `deploy/defectdojo/override.yaml`; with it `capdrop=[ALL]` and `no-new-privileges` | defined by the vendored upstream file; uwsgi and celery write to `/app` and `/tmp` |

- [ ] **Health checks.** `sc ps` shows `healthy` for db, api, worker, gateway (the socket proxy is `FROM scratch` and has none).
- [ ] **Host check.** `bash scripts/check_host.sh` ends `0 failure(s)`; Prometheus `securescan_host_check_ok` is 1.

## 6. Uploads, images and scanner output

- [ ] **Uploads validated (zip guards, size caps).** Create a high-ratio archive and upload it as a zip target: `head -c 300M /dev/zero > z && zip bomb.zip z && rm z` -> the scan is refused with a plain-language `zip.*` problem (ratio limit 100:1). A path-traversal entry (`zip t.zip ../../x`) is refused too. Unit tests: `tests/unit/test_runner_zip.py`, `test_uploads.py`.
- [ ] **Image layers extracted safely.** Scan an image tarball whose layer holds a symlink to `/etc/passwd` and a `.wh.` whiteout: the job ends `completed`, the extracted `rootfs` has no file outside its directory (`tests/unit` for the extractor, M8).
- [ ] **Scanner outputs validated for shape and size.** A job whose output exceeds `max_mb` or is not valid JSON/XML ends `failed` with `outcome_reason` naming the file (`tests/unit/test_runner_validate.py`).

## 7. Secrets and logs

- [ ] **Stored secrets encrypted at rest.** `psql "select kind, left(ciphertext, 4) as prefix from credentials"` -> every prefix is `ss1:`; `sc exec -T worker printenv | grep -i -E 'key|token|secret|password'` shows only `*_FILE` paths.
- [ ] **Token patterns scrubbed from logs.** `sc logs --no-color api worker 2>&1 | grep -E 'ghs_|ghp_|github_pat_|Bearer [A-Za-z0-9._-]{20,}|Token [A-Za-z0-9]{20,}' | head` -> nothing, after a GitHub test, a clone and a DefectDojo import.
- [ ] **No token or key in the data volumes.** `sudo grep -rIl -E 'ghs_|github_pat_|BEGIN (RSA |OPENSSH )?PRIVATE KEY' /var/lib/docker/volumes/securescan_artifacts/_data /var/lib/docker/volumes/securescan_data/_data | head` -> nothing.
- [ ] **Gitleaks runs with `--redact`; findings carry no secret value.** `grep -n -- '--redact' scanners/catalogue.yaml`; scan `python-planted`: the Gitleaks finding in DefectDojo shows `REDACTED`, not the planted value.
- [ ] **ZAP and Nuclei header redaction.** `grep -n -A1 -- '- -rd' scanners/catalogue.d/nuclei.yaml` shows `Authorization,Cookie`; login secrets reach ZAP's plan only as `${ENV}` references (`scanners/catalogue.d/zap.yaml`).
- [ ] **CSV escaping.** In a history export, cells that start with `=`, `+`, `-`, `@`, tab or carriage return begin with `'` (`tests/unit/test_history_filters_and_csv.py`; by hand: a finding titled `=1+1`).
- [ ] **PDF watermark on download.** Download a report PDF: the downloader's name and the time are stamped on every page (`pdftotext report.pdf - | head`).
- [ ] **Secrets never in git.** `git ls-files deploy/secrets deploy/.env deploy/images.env '*.pem' '*.key' '*.age'` lists only `deploy/secrets/.gitkeep` and `deploy/secrets/README.md`; `git log -p --all -S'BEGIN PRIVATE KEY' | head` is empty.

| Secret | Where it lives | Who may read it | Backup |
| --- | --- | --- | --- |
| `securescan_master_key` | `deploy/secrets/` and the vault | root; the api and worker containers | in the encrypted backup set; also in the vault |
| database passwords, `dd_*` keys | `deploy/secrets/` | root; the container that needs it | in the encrypted backup set |
| `oidc_client_secret` | `deploy/secrets/`; Entra holds the value | root; api and worker | in the set; Entra can issue a new one |
| GitHub App private key | encrypted in the database (Settings) or `deploy/secrets/github_app_key_*` | the worker | database in the set; GitHub can issue a new key |
| TLS key and CA | `deploy/secrets/tls/` | root; gateway, db | in the set; the CA issues a new certificate |
| age private key | **not on the machine after setup**: the vault | the restore operator | it is the key to everything else |
| vendor credentials, DAST login profiles | encrypted in the database | the worker, for one job | database in the set |

## 8. TLS

- [ ] **TLS 1.2 or later on the gateway.** `openssl s_client -connect <host>:443 -tls1_1 </dev/null 2>&1 | grep -i 'alert\|error'` (refused) and `-tls1_2` / `-tls1_3` succeed; `sslscan` or `nmap --script ssl-enum-ciphers -p 443 <host>` shows no weak cipher. HSTS header present: `curl -skI $PORTAL | grep -i strict-transport`.
- [ ] **TLS to PostgreSQL, verified.** `psql "select a.usename, a.datname, s.ssl from pg_stat_ssl s join pg_stat_activity a using (pid) where a.datname is not null and a.client_addr is not null"` -> `ssl = t` for `securescan` and `defectdojo`; `sc exec -T api printenv SECURESCAN_DATABASE_URL` ends `sslmode=verify-full&sslrootcert=/run/secrets/tls_ca`; `deploy/defectdojo/override.yaml` sets the same for DefectDojo.
- [ ] **Certificate expiry known.** `openssl x509 -in deploy/secrets/tls/server.crt -noout -enddate` is in the calendar; renewal replaces the files and `sc restart gateway db`.

## 9. Audit log

- [ ] **The log covers the events of the design.** After using the platform for a day: `psql "select action, count(*) from audit_events group by 1 order by 1"` contains, at least: `auth.login`, `auth.login_denied`, `scan.create`, `scan.start`, `scan.finish`, `scan.cancel`, `target.create`, `target.update`, `target.environment_change`,
  `credential.create`, `credential.revoke`, `report.review` (verdict override), `report.download`, `export.history_csv`, `export.report_csv`, `profile.create`, `policy.update`, `integration.github.update`, `defectdojo_account.create`, `image.approve`.
- [ ] **Append-only.** `sc exec -T db psql -U securescan -d securescan -c "update audit_events set action = 'x'"` and the same with `delete from audit_events` -> both fail ("audit_events is append-only").
- [ ] **Every event also goes to the log stream.** `sc logs api | grep -c '"audit"'` is non-zero; the SIEM receives the same lines through Docker's log driver.
- [ ] **Credential use and image approvals are audited.** Approve and deactivate a test image (`docs/runbooks/approving-image-digest.md`): `image.approve` and `image.deactivate` appear with the actor.

## 10. Supply chain

- [ ] **Every image pinned by digest, never `latest`.** `grep -c 'digest: null' deploy/images.lock.yaml` -> 0; `grep -n ':latest' deploy/images.env` -> nothing; `sc config | grep -E 'image:' | grep -v '@sha256:'` lists only the two locally built images (`securescan/backend`, `securescan/gateway`).
- [ ] **Updates only from the allowlist, through the egress proxy, and only after the regression check.** `sc exec -T api python -c "from securescan.config import get_settings; print(get_settings().egress_allow_hosts_updaters)"` is the list of `docs/install.md`; a failed rules update keeps the previous version (`docs/runbooks/content-update-failed.md`); an image proposal is approvable only with `regression_result = passed` or an acknowledged `skipped`.
- [ ] **Dependencies scanned; SBOM for SecureScan's own images.** `docker save securescan/backend:dev -o /tmp/backend.tar`, upload it as an image target of the application "SecureScan" (the first application registered in SecureScan) and scan it: Syft's SBOM is stored as an artifact and Grype's findings are in DefectDojo. Repeat for `securescan/gateway:dev` at each release.
- [ ] **SecureScan is the first application registered in SecureScan.** Inventory shows "SecureScan" with a GitHub target; its weekly scan runs.

## 11. Network posture and residual risks (decisions, not verifications)

| Risk | State in version 1 | Mitigation |
| --- | --- | --- |
| The `backend` network is routable, so the worker and api could reach the internet without the egress proxy | The proxy is policy, not a barrier (the api needs Entra directly; the worker uses the proxy by convention) | Host firewall: allow outbound HTTPS from the machine only to the hosts of `docs/install.md`; review quarterly |
| DefectDojo's containers keep a writable root filesystem and Docker's default capabilities | `defectdojo/override.yaml` is not part of the M11 file set | Apply the snippet in `docs/build-notes/M11.md` (cap_drop, no-new-privileges, limits) after the first successful DefectDojo start |
| The backup set holds the secrets (encrypted) | Chosen so that a restore on a new machine is complete | `BACKUP_INCLUDE_SECRETS=false` if policy forbids; then the vault must hold every secret; the age private key never stays on the machine |
| `/tmp` of the backend containers is not `noexec` | git's credential helper runs from there | Revisit after the first run (`docs/build-notes/M11.md`) |
| SSH deploy-key clones use port 22, which squid does not carry | Open item of M7 | Prefer HTTPS tokens for vendors, or allow SSH egress for the worker at the firewall |
| Scanner output stays on the machine | Scanner output and scanned code never go to an external AI service (Semgrep rules licence) | Nothing to configure; do not add such an integration |
