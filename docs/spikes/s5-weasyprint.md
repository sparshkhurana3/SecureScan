# S5: WeasyPrint in the slim image

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24.

## Purpose

Prove that WeasyPrint 70 renders a two-page branded report inside the `python:3.14-slim-trixie` backend image with only the apt packages named in
`deploy/backend/Dockerfile`; that Liberation Sans is used; that a restricted `url_fetcher` allows `data:` URLs and files below the template directory and refuses
everything else; and that a pypdf stamp ("Downloaded by Test User on 2026-10-07 10:00 UTC") is extractable text. Produces the final apt package list and a sample PDF.

## Prerequisites

- Docker, network for the image build, `backend/uv.lock` present (`cd backend && uv lock`).
- Files: `spikes/s5-weasyprint/templates/` (`sample.html`, `hostile.html`, `extra.css`, `dot.svg`), `frontend/src/brand/wordmark.svg`.

## How to run

```
sh spikes/s5-weasyprint/run.sh
git add docs/spikes/weasyprint-sample.pdf
```

The script builds the image, lists the apt packages, renders twice (plain container, then hardened with `--read-only` and tmpfs), asserts as it goes and copies the
stamped PDF to `docs/spikes/weasyprint-sample.pdf`. Open the PDF and look at it: layout, badges, page numbers, fonts, special characters.

## What to record

| Fact | Value |
| --- | --- |
| Versions: Python, WeasyPrint, pydyf, pypdf; is the class-based `URLFetcher` API present? | |
| Image build time and size | |
| Final apt package list (manually installed; plus pango, harfbuzz, fontconfig, liberation, cairo packages with versions) | |
| Any missing native library error and the package that fixed it | |
| Render time for the two-page sample; PDF size | |
| Fonts embedded (names) | |
| Page numbers `Page n of 2` extractable | |
| Local stylesheet and image fetched; nothing blocked in the legitimate template | |
| Hostile template: each of http, https, ftp, `file:///etc/passwd`, `file:///etc/hostname`, `@import`, `../render.py` refused? PDF still produced? | |
| WeasyPrint log lines for refused resources (warning text) | |
| Stamp text extractable on both pages; original text still extractable | |
| Hardened run (`--read-only`, tmpfs `/tmp` and `~/.cache`): works? which path must be writable (fontconfig cache)? | |
| Visual check of the PDF (what looked wrong, if anything) | |

## Decision

(empty)

- Final apt package line for `deploy/backend/Dockerfile`:
- `url_fetcher` policy to copy into `securescan/reports/` (M5):
- Writable paths the api/worker containers need for rendering:

## Deviations from the design

(empty)
