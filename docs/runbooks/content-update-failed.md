# Runbook: a content update failed, and rollback

"Content" is what scanners read besides their code: the Semgrep rules, the Nuclei templates, the Grype vulnerability database and the Dependency-Check (NVD) data.
Use this runbook when `SecureScanVulnerabilityDatabaseStale` or `SecureScanRulesOrTemplatesStale` fires, when the failure rate of a tool jumps right after an update
(`SecureScanToolFailureRate`), or when scans report fewer findings than before.

How it is meant to work (design, "Updates over the internet"): the weekly updater (Saturday 03:00 UTC) fetches new rules and templates, runs the **regression suite**
(`scanners/regression/`), and only then switches the `semgrep/rules` and `nuclei-templates` symlinks and records a `content_versions` row. On failure it keeps the previous
version and raises the alert metric. The Grype and NVD databases carry data, not logic, so they update daily without a gate.

Shorthand `sc`, `psql`: `docs/install.md`.

## 1. What failed?

```
psql "select feed, version, active, regression_result, fetched_at, built_at from content_versions order by fetched_at desc limit 12"
sc logs --since 24h worker 2>&1 | grep -i -E 'update|regression|content'
```

Settings -> scanner health shows the age of every feed (limits: 7 days for the databases, 30 days for rules and templates).

| You see | Meaning | Section |
| --- | --- | --- |
| no new row for the feed, errors about a host | the download failed (egress, DNS, GitHub or NVD outage) | 2 |
| a new row with `regression_result = failed`, `active = false` | the new content lost a verified finding; the previous version stays active | 3 |
| a new row `active = true` and scans behave badly | the regression suite did not cover the problem | 4 |
| Grype jobs fail with a database error | the database schema is newer than the Grype image | 5 |
| Dependency-Check scans are blocked | the first NVD update has not succeeded yet | 2 |

## 2. A download failed

- Hosts the updaters may reach: `SECURESCAN_EGRESS_ALLOW_HOSTS_UPDATERS` (default list in `docs/install.md`). A new host needed by an upstream change must be added there and the egress proxy recreated (`docker rm -f securescan-egress`).
- Test from the machine: `bash scripts/check_host.sh --network`.
- NVD: check the API key in Settings (credentials; it expires or may be rate-limited); NVD outages are common. Use the configured mirror fallback (`--nvdDatafeed` URL, Settings) until it recovers.
- Retry now: the daily tasks run again at their time; to run one at once ask the code owner (the tasks are `grype_db_update`, `nvd_update`, `rules_and_templates_update`).

The data stays as it was; scans keep using the last good version, which is why the alert is about *age*.

## 3. The regression suite refused the new rules or templates

This is the gate working. Do **not** promote the content by hand.

```
psql "select regression_detail from content_versions where regression_result = 'failed' order by fetched_at desc limit 1"
```

The detail lists, per application and tool, the expected findings that disappeared (`missing`). Decide:

1. A rule was removed or renamed upstream on purpose: check the upstream change log; if the weakness is still real the rules are worse than before. Keep the old version (nothing to do) and ask the code owner to update the expectation in
   `backend/tests/fixtures/sample-apps/<app>/expected-findings.yaml` **in a commit that says why** (`scanners/regression/README.md`, rule 4).
2. A rule is broken (the suite found a loss of detection): keep the old version; report upstream.
3. The run itself was flaky (a tool `error`, a timeout): run the suite again, see "Run the suite by hand" below.

## 4. A promoted version misbehaves: roll back

The content volume keeps dated directories and symbolic links (`/var/lib/securescan/content`, `semgrep/rules -> rules-<commit>`, `nuclei-templates -> nuclei-templates-<date>`).

```
IMG=$(grep '^IMG_PYTHON=' deploy/images.env | cut -d= -f2-)
docker run --rm -v securescan_content:/c --network none --entrypoint sh "$IMG" -c 'ls -l /c /c/semgrep'
# point the link at the previous directory (example for Semgrep):
docker run --rm -v securescan_content:/c --network none --user 1000:1000 --entrypoint sh "$IMG" -c 'ln -sfn rules-<previous commit> /c/semgrep/rules'
```

Then record it in the database, in one transaction, so the active row matches the link (scans record the content version they used):

```
psql "begin; update content_versions set active = false where feed = 'semgrep_rules' and active; update content_versions set active = true, activated_at = now() where feed = 'semgrep_rules' and version = '<previous version>'; commit;"
```

(Nuclei: feed `nuclei_templates`. At most one row per feed may be active; the database enforces it.) The scans started from now on use the old rules; running jobs finish with what they started with.

## 5. Grype: the database schema moved on

Grype retires an old database schema about a year after a new one ships. A Grype job that fails with a schema or "database too old" message needs a newer Grype image:
`docs/runbooks/approving-image-digest.md` (approve the proposed `grype` image; the quarterly bump in the upkeep calendar avoids this). With `GRYPE_DB_VALIDATE_AGE=true` a database older than the limit fails the job visibly instead of reporting against old data: that is intended.

## Run the suite by hand

```
sc exec worker python -m securescan.domain.regression check               # the expectation files parse
sc exec worker python -m securescan.domain.regression run --kind content  # Semgrep over the planted apps
sc exec worker python -m securescan.domain.regression run --kind all --json
```

Exit code 0 passed, 1 failed or error, 2 nothing asserted (no expectation is `verified: true` yet: the suite then proves nothing, see `scanners/regression/README.md`).

## Verify and record

- The feed's age gauge is back under its limit; `content_versions` shows exactly one active row per feed; a scan of `python-planted` reports the same titles as before.
- Write down which version was active, which was rejected and why.
