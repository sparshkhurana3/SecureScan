# S6: GitHub App

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24 with a real App.

## Purpose

Prove the GitHub integration end to end: an App JWT, a one-repository installation token with `contents: read`, repository listing for the nightly discovery,
the default-branch head SHA for the poller, and a clone with a credential helper (never a token in the URL) that keeps full history and all refs, drops the
remote, and leaves no token anywhere under `.git`.

## Prerequisites

- A test GitHub App owned by the user's organisation or personal account: permissions Contents: read and Metadata: read, webhook disabled, installed on at least one repository.
- App client ID (or numeric App ID), installation ID, private key saved as `deploy/secrets/github_app_key_1` (git-ignored; never commit a `.pem`).
- `git` on the host; outbound HTTPS to `api.github.com` and `github.com`.

## How to run

```
export GITHUB_APP_CLIENT_ID=<client id>            # or GITHUB_APP_ID=<numeric id>
export GITHUB_INSTALLATION_ID=<installation id>
export GITHUB_REPO=<owner>/<repo>
export GITHUB_APP_KEY_FILE=deploy/secrets/github_app_key_1
uv run --project backend python spikes/s6/run.py
```

For GitHub Enterprise Cloud with data residency or Server set `GITHUB_API_URL` and `GITHUB_GIT_URL`. `GITHUB_API_VERSION` defaults to `2026-03-10`.

## What to record

| Fact | Value |
| --- | --- |
| JWT length; `iss` kind that GitHub accepted (client ID vs App ID) | |
| `GET /app`: slug, permissions, events (webhook off?) | |
| Installation: repository selection, permissions, suspended | |
| Installation token: length, prefix, `expires_at`, lifetime in minutes | |
| Token permissions and repositories as returned (scoped to one repo?) | |
| Status for a repository outside the token's scope | |
| `installation/repositories`: total, pages fetched, seconds | |
| Default branch and head SHA; does the cloned `HEAD` equal it? | |
| Rate limit for an installation token (`rate_limit_core`) | |
| Clone: seconds, shallow? (must be false), commits reachable from all refs | |
| Remote-tracking branches before removal; local branches created from them; commits before/after `git remote remove origin` | |
| `.git/config` after removal (paste) | |
| Files under `.git` containing the token or its markers (must be none) | |
| `git config --list --show-origin` free of the token? | |
| Revocation: `DELETE /installation/token` status; status of the revoked token afterwards | |

## Decision

(empty)

- Clone procedure for `runner/sources/github.py` (M3), including the step that keeps all branches before the remote is removed:
- Which refs are available to Gitleaks (pull request refs are not fetched by default):
- Token handling: mint per job, scope, revoke after the clone:
- `X-GitHub-Api-Version` value to configure:

## Deviations from the design

(empty)
