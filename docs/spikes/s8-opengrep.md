# S8: Opengrep

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24. One hour; the outcome is optional.

## Purpose

Find out whether the Opengrep CLI (the LGPL fork of Semgrep) runs the same local rules on `js-planted`, writes SARIF, reports comparable findings, whether an official
container image exists, and whether DefectDojo's `SARIF` import accepts the output. Expected decision: deferred, fallback engine only (design: "Replacing CodeQL").

## Prerequisites

- Network access to GitHub releases.
- The Semgrep rules directory from S7 (`sh spikes/s7/prefetch.sh semgrep`); the Semgrep fixture `semgrep.json` from S7 for the comparison.
- Optional: a running S1 DefectDojo and the `securescan-sync` token (`S8_DD_URL`, `S8_DD_TOKEN`).

## How to run

```
sh spikes/s7/prefetch.sh semgrep
uv run --project backend python spikes/s8/run.py
```

## What to record

| Fact | Value |
| --- | --- |
| Release tag and publish date; asset used; binary size | |
| SHA-256 matches the digest GitHub lists? signature assets present (not verified by the script) | |
| `opengrep --version`; flags of the Semgrep command line supported (`scan_flags_in_help`) | |
| Scan exit code and seconds | |
| SARIF: version, driver name and version, number of results, `partialFingerprints` present? | |
| Native JSON: number of results, fingerprint field present? | |
| Semgrep fixture: number of results; rule ids only in Semgrep, only in Opengrep, in both | |
| Docker Hub `opengrep/opengrep` status; `ghcr.io/opengrep/opengrep` manifest exit code | |
| DefectDojo `SARIF` import: status, findings | |

## Decision

(empty)

One paragraph for this file, and one line in `docs/decisions.md` (expected: deferred, fallback engine only):

## Deviations from the design

(empty)
