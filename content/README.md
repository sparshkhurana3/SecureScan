# Scanner content

Scanners never download anything while they scan. Rules, templates and vulnerability data live on the **content volume**
(`securescan_content`, mounted in the worker at `/var/lib/securescan/content`) and are filled by updaters that the worker
starts on a schedule. Each scan records the versions it used (`scan_jobs.content_versions`), and Settings, Content shows
the history (`GET /api/v1/content-versions`) and the feed ages (`GET /api/v1/scanner-health`).

This directory of the repository holds only the pins and notes. The content itself is never committed.

## Layout on the content volume

| Path | Written by | Read by | Notes |
| --- | --- | --- | --- |
| `semgrep/rules-<commit>/` | weekly rules update | nobody directly | A filtered copy of `semgrep/semgrep-rules` at that commit (licence-filtered, rule files only, `LICENSE` and `BUNDLE.json` kept). Never edited. |
| `semgrep/rules` | weekly rules update | Semgrep scans (the resolved directory is mounted at `/content/semgrep/rules`) | Symlink to `rules-<commit>`, switched atomically after the regression gate passed. |
| `nuclei-templates-<yyyymmdd>/` | weekly templates update | nobody directly | Output of `nuclei -ut -ud`, kept for the last `SECURESCAN_CONTENT_KEEP_VERSIONS` versions. |
| `nuclei-templates` | weekly templates update | Nuclei scans (M9 mounts the resolved directory) | Symlink to the active dated directory. |
| `grype-db/` | daily Grype update (07:30 UTC, after Anchore's 06:00 build) | Grype scans | The only writer is the updater container; scans mount it read-only when `SECURESCAN_GRYPE_DB_READ_ONLY=true`. |
| `odc-data/` | daily Dependency-Check update (03:00 UTC) | Dependency-Check scans | H2 database of the NVD data. Dependency-Check scans are blocked until the first update succeeded. |

The directories under the content root are world-writable on purpose (mode 0777, created by the worker): the updater and
scanner containers run as uid 1000 with all capabilities dropped.

## The Semgrep rules pin: `semgrep-rules.lock`

`content/semgrep-rules.lock` (YAML) names the repository, the pinned `commit` (or `auto: true` for the newest), the licence
filter and the directories that never hold rules. The worker finds it through `SECURESCAN_SEMGREP_RULES_LOCK_FILE` or next to
the scanners directory (`<scanners dir>/../content/semgrep-rules.lock`); the Compose file mounts it read-only at
`/app/content/semgrep-rules.lock`. `SECURESCAN_SEMGREP_RULES_COMMIT` overrides the pin without touching the file.

What the filter does, per rule file of the clone:

1. skips files in `drop_directories` and every file that is not a `.yaml` or `.yml` rule file (test sources next to the
   rules, `*.test.yaml`, statistics, CI definitions);
2. parses the YAML; a file that is not a mapping with a `rules` list is not a rule file and is dropped;
3. applies the licence policy to every rule's `metadata.license` (see the comments in the lock file). **The AGPL-3.0
   `trailofbits.*` rules and any other licence outside the allowlist are dropped.** The Semgrep Rules License v1.0 permits
   internal business use only: the rules are never offered for download, reports are internal documents by default, and the
   licence notice (`LICENSE` of the repository) is copied into every bundle.

The bundle keeps the repository's directory layout, so rule ids (which Semgrep derives from the path below the `--config`
directory) are identical from one version to the next for an unchanged rule.

## Promotion and the regression gate

A new rules version or template directory is built beside the active one and promoted only when `run_regression(kind)` passes
(`backend/securescan/jobs/updaters.py`): for Semgrep, the candidate rules run against the planted sample apps and every
`verified: true` entry of `backend/tests/fixtures/sample-apps/*/expected-findings.yaml` (format in
`scanners/regression/README.md`) must still be found; for Nuclei, `nuclei -validate` must accept the templates. On success the
symlink is switched and a `content_versions` row becomes active; on failure the previous version stays active, the candidate is
kept under `<name>.rejected` for inspection and the metric `securescan_content_update_failed{feed}` is set to 1.
The first installation (no active version yet) is promoted without the gate, because there is nothing to regress against.

## What an Admin does

* Sets the NVD API key once (`PUT /api/v1/content/nvd-key`, or `SECURESCAN_NVD_API_KEY_FILE`). Without a key the NVD update is
  skipped with a warning, unless `SECURESCAN_NVD_DATAFEED_URL` names a mirror.
* Starts an update by hand from Settings, Content (`POST /api/v1/content-versions/updates`) after the first installation or after
  a failed run. The worker also queues the first update of every empty feed at start-up (`SECURESCAN_CONTENT_BOOTSTRAP`).
* Reviews the feed-age alerts: databases older than 7 days, rules and templates older than 30 days.
