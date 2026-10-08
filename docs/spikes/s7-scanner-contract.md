# S7: Scanner container contract

Status: **template, not yet run.** All cells below are empty until the scripts have been run on Ubuntu 24. This file is the input M3 and M8 copy into `scanners/catalogue.yaml`.

## Purpose

Run every scanner image with the M3 HostConfig (`ReadonlyRootfs`, `CapDrop ALL`, `no-new-privileges`, no network, `PidsLimit`, memory and CPU limits, read-only source,
read-write `out`, tmpfs) against the planted apps and record, per image: the uid, the paths that must be writable, whether content volumes can be read-only, the exact
command that worked, exit codes (clean target, findings, broken input), and output file names. Produce one real report per scanner as a contract-test fixture.

## Prerequisites

- Docker, network for `prefetch.sh`; after that the scans run with `--network none`.
- `NVD_API_KEY` (free) for the Dependency-Check update, which takes 20+ minutes: start it first.
- The planted jar `backend/tests/fixtures/sample-apps/java-planted/target/java-planted.jar` (`sh scripts/build_planted_jar.sh`).
- The two SHA-256 values for the SpotBugs image (`scanners/spotbugs/README.md`).

## How to run

```
NVD_API_KEY=... sh spikes/s7/odc_update.sh               # first; check later with: sh spikes/s7/odc_update.sh status
sh spikes/s7/prefetch.sh all                              # images, Grype DB, Nuclei templates, Semgrep rules
SPOTBUGS_SHA256=... FSB_SHA256=... sh spikes/s7/build_spotbugs.sh
sh spikes/s7/run_all.sh                                   # or: sh spikes/s7/run_all.sh semgrep gitleaks
```

SonarQube is spike S3. The script does not stop at failures (exit codes are the data); its exit code is 1 when a hardened run failed or an expected output is missing.
It prints a summary in markdown at the end; logs are in `spikes/s7/.data/logs/`, results in `spikes/s7/.data/results.tsv`.

## What to record

One table per image (copy the summary rows, then fill in what the script cannot see). Pinned digest of each image as pulled by `prefetch.sh images`:

| Image | Digest | Configured user | Runtime uid:gid | HOME |
| --- | --- | --- | --- | --- |
| semgrep/semgrep (`-nonroot`) | | | | |
| gitleaks | | | | |
| syft | | | | |
| grype | | | | |
| dependency-check | | | | |
| securescan/spotbugs-fsb | | | | |
| sonar-scanner-cli (from S3) | | | | |
| zap | | | | |
| nuclei | | | | |

Per image:

| Image | Writable paths needed (`docker diff`) | tmpfs needed (and `exec`?) | Content volume read-only works? | Command that worked | Exit: clean / findings / broken | Output files (owner, mode) |
| --- | --- | --- | --- | --- | --- | --- |
| semgrep | | | rules mount | | | |
| gitleaks (dir) | | | | | | |
| gitleaks (git; root, non-root, `safe.directory`) | | | | | | |
| syft | | | | | | |
| grype | | | Grype DB ro? | | also `--fail-on high`, stale DB | |
| dependency-check | | | `odc_data` ro? two concurrent containers on one volume? | | | |
| spotbugs | | | | which output form worked | | |
| zap | | | | | | |
| nuclei | | | templates ro? | | | |

Further facts:

| Fact | Value |
| --- | --- |
| Flags from the plan that the pinned images do not list in `--help` (`flags_not_in_help` and `optional_flags_dropped_because_not_in_help`) | |
| Dependency-Check: property name that carries the NVD key in `--propertyfile` (expected `nvd.api.key`; see `.data/odc-update.log`) | |
| Dependency-Check: exit code 14 meaning; behaviour with `--noupdate` on an empty or read-only data volume | |
| Grype: behaviour with a stale database (`GRYPE_DB_MAX_ALLOWED_BUILT_AGE=1h`): message and exit code | |
| Gitleaks as root with `--cap-drop ALL`: does it read the workspace? Non-root and `safe.directory` through `GIT_CONFIG_*` | |
| SpotBugs: `-xml:withMessages=FILE` accepted or `-output` needed; JVM heap default (768 MB) enough for the planted jar? | |
| ZAP: report file name produced; exit codes; can it reach the internet from the internal network (must not) | |
| Nuclei: is `nuclei.json` written when there are no results; config dir and templates directory write needs | |
| Fixture reports written (name, source app, size, finding count) | |
| Planted-app findings per tool compared with `expected-findings.yaml` (which entries can be set to `verified: true`) | |

## Decision

(empty)

- Catalogue entries (user, mounts, tmpfs, command, exit-code mapping, outputs) per tool, ready to paste into `scanners/catalogue.yaml`:
- Whether the workspace permission model (directories 0775 owned by uid 1000, files world-readable) works for root images with all capabilities dropped:
- Which content mounts are read-only and which tools need `max_parallel: 1`:

## Deviations from the design

(empty)
