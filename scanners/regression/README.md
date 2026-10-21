# Regression suite: expected findings per fixture app and tool

The regression suite answers one question: after a change to the scanner content or images, does each tool still report what it
reported before? The weekly Semgrep rules and Nuclei templates update (M8) runs it before promoting new content; the monthly
image-update proposals (M11) run it against each candidate image before an Admin can approve it.

The runner is `backend/securescan/domain/regression.py` (`run_regression(kind)`). It scans each planted app through the **normal scan
path** (queue, worker, DefectDojo import, history rows), then compares what the tools reported with the expectations below.

## Where the expectations live

- Per planted app: `backend/tests/fixtures/sample-apps/<app>/expected-findings.yaml` (the source of truth, next to the code
  that plants the weakness).
- This directory holds the runner's configuration (`suite.yaml`: which apps and tools each kind of run covers) and the expectation
  files of the optional external apps (`juice-shop.yaml`, `webgoat.yaml`) in the same format, plus `broken-rules/` for the drill below.

## Format (`schema_version: 1`)

```yaml
app: java-planted
schema_version: 1
tools:
  semgrep:                      # one list per tool in the catalogue; an empty list means "nothing asserted yet"
    - id: java-sql-injection    # stable local id, unique within the file; never reused for a different weakness
      expect_category: "SQL injection: query built by string concatenation with request input"
      file: src/main/java/.../UserServlet.java   # optional: path relative to the app root
      line: 25                  # optional: line of the planted weakness (informational, not matched exactly)
      verified: false           # true only after a real run produced a matching finding
      note: "free text"         # optional
      rule_id: null             # optional: filled from a real report once verified; never guessed
      vulnerability_id: null    # optional, for dependency scanners (for example CVE-2021-44228)
```

Rules for writing entries:

1. An entry states a weakness that is certain from reading the planted code (or manifest). It does not promise that a tool finds it.
2. `expect_category` is free text for humans and for the first, fuzzy matching pass. It is not a rule id.
3. `verified: false` until the first run on Ubuntu (spike S7) shows a finding for it; then set `verified: true` and fill `rule_id`
   (or `vulnerability_id`) from the real report. A tool that does not report a weakness is a finding about the tool: keep the entry
   with `verified: false` and write a `note`, or remove it and record the decision in `docs/decisions.md`.
4. Do not add entries to make a failing run pass. Tighten or relax them in a commit that says why.

Tool keys: `semgrep`, `gitleaks`, `grype` (the `syft-grype` job), `spotbugs`, `nuclei`.

## How the runner matches

For each entry the runner looks at the findings the tool's job added to the history for that scan:

1. `rule_id` set: a finding whose title contains it (DefectDojo's Semgrep parser uses the rule id as the title).
2. `vulnerability_id` set, or a CVE written in `expect_category`: a finding whose CVE field or title carries it.
3. Otherwise the key words of `expect_category` (stop words removed, prefix match on the first five letters): at least 60 percent
   of them in the title, or 34 percent when the finding is in the entry's `file`.

Result per app and tool:

| Status | Meaning |
| --- | --- |
| `passed` | every `verified: true` entry matched |
| `failed` | a `verified: true` entry did not match (listed as `missing`) |
| `error` | the job failed or timed out, the scan could not run, or the candidate image was not the one that ran |
| `unasserted` | the tool has no `verified: true` entry yet. Entries still `verified: false` that a run did report are listed as "reported, not yet verified": candidates for `verified: true` |
| `skipped` | the tool did not take part in the scan |

A suite is `failed` when any tool failed or errored, `passed` when at least one tool passed and none failed, and **`unasserted`
when nothing was asserted**. An unasserted suite proves nothing: the image gate stores it as `skipped` and an Admin must acknowledge
that nothing was tested. Until the first real run (spike S7) every entry is `verified: false`, so the suite is unasserted.

Titles are compared as sets, not counts. `RegressionReport.titles_by_tool()` of one run can be passed as `baseline_titles` to the
next one; titles that disappeared are listed (a warning, because a rules update may remove rules on purpose). That is how the M8
acceptance "two Semgrep runs across a rules update produce identical titles for unchanged rules" is checked.

## Running it

```
python scripts/dev.py test regression            # once dev.py calls the command below (see docs/build-notes/M11.md)
docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env -f deploy/compose.yaml \
    exec worker python -m securescan.domain.regression run --kind all
docker compose ... exec worker python -m securescan.domain.regression check     # parse the expectation files only
```

Exit codes of `run`: 0 passed, 1 failed or error, 2 nothing asserted (`--allow-unasserted` turns 2 into 0). `--kind` is `content`,
`image`, `external`, `dast` or `all` (`image` plus `external`; `content` is a subset of `image`, `dast` needs a target); `--app` and `--tool` narrow it. The fixtures directory is found
through `SECURESCAN_REGRESSION_FIXTURES_DIR`, else `backend/tests/fixtures/sample-apps` (mounted into the worker at
`/app/regression/sample-apps`). Each scan creates the application `regression-<app>` (tag `regression`) with a zip target; the
scans, reports and DefectDojo products it leaves behind are real history, kept like any other.

## Optional external apps (Juice Shop, WebGoat)

`python scripts/dev.py fetch-fixtures` clones them into `fixtures/external/` on the host. Copy (or bind-mount into the worker)
`fixtures/external/juice-shop` and `webgoat` into the fixtures directory, then `run --kind external`. A missing directory is
skipped with a note, never a failure. The DAST regression (`--kind dast`) needs a Juice Shop running on a UAT network and
`SECURESCAN_REGRESSION_DAST_URL`; without it the kind is skipped.

## The "broken rule" drill (acceptance check)

The suite must fail when a rule is broken. With at least one verified Semgrep entry:

1. Create a candidate rules directory in the content volume (`/var/lib/securescan/content/semgrep/rules-drill/`) holding only
   `broken-rules/invalid-rule.yaml` (Semgrep must fail: `error`) or only `broken-rules/never-matches.yaml` (verified entries
   disappear: `failed`).
2. Point the Semgrep scan at it the way the M8 updater does for a candidate (its `tool_options`), run `--kind content --tool semgrep`.
3. Expect exit code 1. Delete the directory.

## Adding a tool or an app

1. New tool: add it as a key under `tools:` in every app file (empty list is fine), add it to the lists in `suite.yaml`, and, for the
   image gate, to `REGRESSION_TOOLS` in `backend/securescan/domain/image_updates.py`.
2. New app: add `backend/tests/fixtures/sample-apps/<app>/` with the planted weakness, an `expected-findings.yaml` and a line in
   `backend/tests/fixtures/sample-apps/README.md`, then list it in `suite.yaml`.
3. Refresh `backend/tests/fixtures/reports/<tool report>` whenever the tool's image is bumped (see `scanners/README.md`).
