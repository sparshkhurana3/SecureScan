# Runbook: GitHub App private key rotation

The GitHub App's private key signs the short-lived tokens SecureScan uses to read the corporate repositories. SecureScan holds **two key slots** so a rotation needs no downtime: the old key keeps working
until the new one is proven. Rotate yearly (the upkeep calendar), when a person who could read the key leaves, or at once if the key may have leaked (then skip the patience and delete the old key in step 4 first).

Where the keys are: either encrypted in the database (Settings -> GitHub connection, slots 1 and 2, with an *active* slot) or as the files `deploy/secrets/github_app_key_1` and `_2` (`SECURESCAN_GITHUB_APP_KEY_1_FILE`);
a key uploaded in Settings wins over the file. An installation token is minted per job, scoped to one repository with `contents: read`, kept in memory only and discarded after the clone.

## Steps

1. **Create the new key.** GitHub -> the organisation -> Settings -> Developer settings -> GitHub Apps -> SecureScan -> General -> Private keys -> *Generate a private key*. A `.pem` downloads; GitHub keeps the old key valid. (An App can hold several keys.)
2. **Give it to SecureScan in the free slot.** Settings -> GitHub connection -> upload the PEM into the slot that is **not** active (the fingerprint shown must match the one GitHub lists next to the key). With files: `sudo install -m 0644 new.pem deploy/secrets/github_app_key_2` and recreate the worker (`sc up -d --force-recreate worker`).
   Then delete your local copy: `shred -u new.pem` (the vault copy, if policy keeps one, is the only other).
3. **Prove it and switch.** Press *Test* for the new slot (it mints an App token and lists the installation's repositories); set the new slot *active*; press *Discover*. Wait for the next poll (10 minutes) or trigger a scan of a small repository: a clone succeeds, the audit log shows `integration.github.update`.
4. **Retire the old key.** In GitHub delete the old key (Private keys -> Delete; GitHub lists them by fingerprint and last-used date). In Settings clear the old slot. From now on only the new key can sign.
5. **Next time** the roles of the slots swap: you upload into the slot you just cleared.

## If things go wrong

- *Test fails with 401 or "A JSON web token could not be decoded"*: the PEM was damaged on the way (a line break lost) or belongs to another App; upload it again, check the App ID or Client ID in the connection.
- *The poller reports "bad credentials" after step 4*: you deleted the key that was still active. Generate another key (step 1), upload it, activate it. Scans of repositories already cloned are not affected; polling and discovery pause until then (`SecureScanGitHubPollStale` fires after an hour).
- *Clock skew*: the token's `iat` is back-dated 60 seconds; if the machine's clock is more than a minute off, every JWT is refused. `timedatectl status`; fix NTP (`scripts/check_host.sh` warns about it).

## Related

- GitHub removes keys and tokens that were **unused for a year**: vendor deploy keys and vendor-issued tokens (`credential-rotation.md`, the calendar and `SecureScanCredentialsExpiring`) are re-established with the vendor at each yearly re-assessment.
- Changing the App's **permissions** needs the organisation owner's approval of the new permissions; SecureScan needs only Contents: read and Metadata: read, so there should be no reason to change them.
- If the App itself is replaced (a new App ID), enter the new App ID or Client ID, the installation ID and a new key in Settings -> GitHub connection, run *Discover*, and delete the old App in GitHub afterwards.

## Record

Date, who, the fingerprint of the new key (never the key), the audit event ids.
