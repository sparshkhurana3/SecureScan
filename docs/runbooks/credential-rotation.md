# Runbook: credential and master-key rotation

Rotate on a schedule (yearly review) and at once when a person who knew a secret leaves or a secret may have leaked. Secrets are files in `deploy/secrets/` (Docker secrets, mounted at `/run/secrets/<name>`); stored
credentials are encrypted in the database under the master key. A list of every secret and where it lives: `docs/security-checklist.md`, section 7. GitHub App keys have their own runbook
(`github-app-key-rotation.md`).

General rules: back up first (`bash scripts/backup.sh`); change one secret at a time; never put a value on a command line (use `printf` into the file, or an editor); keep the old value in the vault until the new one is proven; write secret files without a
trailing newline where you can (the loaders strip it anyway); record who rotated what in the operations log, never the value.

Shorthand `sc`, `psql`: `docs/install.md`.

## Rotation calendar

| Secret | How often | Notes |
| --- | --- | --- |
| Entra client secret (`oidc_client_secret`) | before it expires (the Entra portal shows the date) | an expired secret locks everybody out: set a reminder 30 days ahead |
| TLS certificate (`tls/server.crt`, `server.key`) | before it expires | one certificate serves the gateway and PostgreSQL |
| GitHub App key | yearly | `github-app-key-rotation.md` |
| Master key (`securescan_master_key`) | every two years, and on suspicion | section 2 |
| Database passwords | yearly, and on suspicion | section 3 |
| DefectDojo break-glass (`dd_admin_password`) | yearly; after every use | section 4 |
| Vendor tokens, deploy keys, DAST login profiles | per their expiry (`SecureScanCredentialsExpiring` alerts 14 days ahead) | Settings -> credentials: add the new one, then revoke the old one |
| age backup key | when a person with access leaves | section 5 |

## 1. Entra client secret

1. Entra admin centre -> App registrations -> SecureScan -> Certificates and secrets -> New client secret. Copy the value once.
2. `printf '%s' '<value>' | sudo tee deploy/secrets/oidc_client_secret >/dev/null`
3. `sc up -d --force-recreate api worker` (they read the file at start).
4. Sign in with a private browser window. Only then delete the old secret in Entra.

## 2. Master key (encrypts every stored credential)

SecureScan supports two keys at once: the new one encrypts, the previous one still decrypts, and each stored value carries the id of the key that encrypted it. Rotating is therefore: add the new key, re-encrypt everything, remove the old key.

**Step 1.** Back up: `bash scripts/backup.sh`.

**Step 2.** Keep the old key under another name and create the new one:

```
sudo cp deploy/secrets/securescan_master_key deploy/secrets/securescan_master_key_previous
python3 -c "import secrets; print(secrets.token_hex(32), end='')" | sudo tee deploy/secrets/securescan_master_key >/dev/null
```

**Step 3.** Give the previous key to the services that decrypt: create `deploy/compose.rotation.yaml` (not committed):

```
services:
  api:       { secrets: [securescan_master_key_previous], environment: { SECURESCAN_MASTER_KEY_PREVIOUS_FILE: /run/secrets/securescan_master_key_previous } }
  worker:    { secrets: [securescan_master_key_previous], environment: { SECURESCAN_MASTER_KEY_PREVIOUS_FILE: /run/secrets/securescan_master_key_previous } }
  dojo-init: { secrets: [securescan_master_key_previous], environment: { SECURESCAN_MASTER_KEY_PREVIOUS_FILE: /run/secrets/securescan_master_key_previous } }
secrets:
  securescan_master_key_previous: { file: ./secrets/securescan_master_key_previous }
```

and start with it:

```
docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml -f deploy/compose.rotation.yaml up -d --force-recreate api worker dojo-init
```

**Step 4.** Re-encrypt every stored secret under the new key (run it once; it is idempotent):

```
sc exec -T worker python - <<'PY'
import asyncio
from sqlalchemy import select
from securescan.db.models.credentials import Credential
from securescan.db.models.users import User
from securescan.db.session import session_scope
from securescan.security.secrets import current_key_id, reencrypt_secret

async def main() -> None:
    credentials = users = 0
    async with session_scope() as db:
        for c in (await db.scalars(select(Credential))).all():
            c.ciphertext = reencrypt_secret(c.ciphertext, "credential:%s" % c.id)
            c.key_id = current_key_id()
            enc = (c.extra or {}).get("password_enc")
            if enc:
                c.extra = {**c.extra, "password_enc": reencrypt_secret(enc, "credential-password:%s" % c.id)}
            credentials += 1
        for u in (await db.scalars(select(User).where(User.dd_initial_secret.is_not(None)))).all():
            u.dd_initial_secret = reencrypt_secret(u.dd_initial_secret, "user-dd:%s" % u.id)
            users += 1
    print("re-encrypted credentials=%d users=%d key=%s" % (credentials, users, current_key_id()))

asyncio.run(main())
PY
```

**Step 5.** Check: `psql "select key_id, count(*) from credentials group by 1"` shows one key id (the new one). In Settings, open GitHub connection and press Test: it still works.

**Step 6.** Remove the previous key: delete `deploy/compose.rotation.yaml` and `deploy/secrets/securescan_master_key_previous`, run `sc up -d --force-recreate api worker dojo-init`, test again.

**Step 7.** Put the new key in the vault; keep the old one there **as long as backups made with it exist** (those sets contain the old key inside their `secrets.tar.age`, so a restore still works, but keep the copy anyway).

If the master key is **lost** and no copy exists, every stored credential (GitHub App key in the database, deploy keys, vendor tokens, DAST logins, DefectDojo tokens) is unreadable: restore the key from a backup set's `secrets.tar.age` (`docs/runbooks/restore.md`), or enter the credentials again in Settings and run `sc up -d dojo-init` to mint the DefectDojo tokens.

## 3. Database passwords

Two roles: `securescan`, `defectdojo` (secrets `securescan_db_password`, `defectdojo_db_password`, and `dd_database_url`, which contains DefectDojo's password and must be rebuilt).

1. Generate: `python3 -c "import secrets; print(secrets.token_hex(24), end='')"`.
2. Change the role, then the file, then restart the users of that role (example for SecureScan):
   ```
   NEW=$(python3 -c "import secrets; print(secrets.token_hex(24), end='')")
   sc exec -T db psql -U postgres -c "ALTER ROLE securescan PASSWORD '$NEW'"
   printf '%s' "$NEW" | sudo tee deploy/secrets/securescan_db_password >/dev/null
   sc up -d --force-recreate migrate api worker dojo-init
   ```
   For DefectDojo: also rebuild `deploy/secrets/dd_database_url` (`python3 -c "import urllib.parse as p; print('postgresql://defectdojo:%s@db:5432/defectdojo?sslmode=verify-full&sslrootcert=/run/secrets/tls_ca' % p.quote('<new>', safe=''), end='')"`, written with `tee`) and `sc restart uwsgi celeryworker celerybeat initializer`.
3. The `ALTER ROLE` statement contains the password; clear the shell history of that session (`history -c`), or use `\password securescan` in an interactive `psql` instead.
4. `postgres_superuser_password` is used only by the `db` container and the backup (through the local socket, no password): change it by `ALTER ROLE postgres PASSWORD ...`, update the file, `sc up -d --force-recreate db` (a short outage).

## 4. Break-glass accounts

- **DefectDojo `admin`**: sign in through the gateway, change the password in DefectDojo (profile), write the new value to `deploy/secrets/dd_admin_password` and to the vault, `sc up -d --force-recreate dojo-init`. Every use raises `SecureScanBreakGlassLogin`.
- If someone used a break-glass account without a reason, treat it as an incident: rotate it, read the audit log and the tool's own log for that time.

## 5. The age backup key

A new key pair makes older backup sets unreadable *with the new key* only: keep every old private key as long as sets encrypted for it exist.

1. `age-keygen -o /root/new_backup_age_key` (on a trusted machine); store the private key in the vault.
2. `deploy/.env`: `BACKUP_AGE_RECIPIENT=<new public key>` (or replace `deploy/secrets/backup_age_key`).
3. `bash scripts/backup.sh --check`, then a full `bash scripts/backup.sh`, then `bash scripts/restore.sh <new set> --identity <new key> --check`.
4. Keep the old private key in the vault until the last set encrypted for it has aged out of the off-machine target.

## Record

Date, secret, who, which backup set was taken before, and the checks of the section you followed.
