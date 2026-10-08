# S4: Entra ID OIDC with app roles

Status: **template, not yet run.** All cells below are empty until the script has been run on Ubuntu 24 with real credentials.

## Purpose

Prove the sign-in flow SecureScan will use: OIDC authorization code with PKCE through Authlib, redirect `https://securescan.localtest.me:8443/api/v1/auth/callback`,
and record the exact shape of the ID token, in particular the `roles` claim (`Admin` or `Analyst`), what happens for a user without a role, and what
"assignment required" does for an unassigned user. The result feeds `securescan/auth/oidc.py` and `roles.py` (M2) and the Entra instructions in `deploy/README.md`.

## Prerequisites

- An Entra ID test tenant and an app registration (or `ghcr.io/navikt/mock-oauth2-server`; fall back to Keycloak as the plan describes).
- App registration: redirect URI above (platform "Web"), two app roles with values `Admin` and `Analyst` (allowed member types: users/groups), a client secret.
  Enterprise application: "Assignment required" = yes; test users assigned: one Admin, one Analyst, one with both, one assigned with no role (if the portal allows it),
  one not assigned.
- `python scripts/dev.py certs` run (for the https callback listener; `deploy/secrets/tls/server.crt` and `server.key`), or an `http://localhost:<port>` redirect URI registered instead.
- The browser must reach `https://securescan.localtest.me:8443/...` on the machine running the script (it resolves to 127.0.0.1), or use `--paste`.

## How to run

```
export OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
export OIDC_CLIENT_ID=<application (client) id>
export OIDC_CLIENT_SECRET_FILE=deploy/secrets/oidc_client_secret
uv run --project backend python spikes/s4/run.py --expect admin      # sign in as the Admin user
uv run --project backend python spikes/s4/run.py --expect analyst
uv run --project backend python spikes/s4/run.py --expect any        # the user with both roles; note the prototype rule
uv run --project backend python spikes/s4/run.py --expect norole     # a user without a role
uv run --project backend python spikes/s4/run.py --expect denied     # an unassigned user
```

Open the printed URL in a browser. Identifying claim values are hidden unless `S4_SHOW_CLAIMS=1`. For the mock provider with a private CA set `S4_VERIFY=<ca bundle>`.

## What to record

| Fact | Value |
| --- | --- |
| Issuer, discovery endpoints, `code_challenge_methods_supported` | |
| Token endpoint authentication method used and accepted | |
| Scopes requested and returned | |
| Callback query keys; state and nonce check | |
| Token response keys; `expires_in`; refresh token present? | |
| ID token header (`alg`, `kid`); signing key found in the JWKS | |
| `ver` and `iss` shape (v2.0 issuer matches the configured one?) | |
| Claims present (names and types) | |
| `roles` claim: type and value for Admin / Analyst / both / no role | |
| `groups` claim present? overage markers (`hasgroups`, `_claim_names`)? | |
| ID token lifetime (`exp - iat`) | |
| Authorization code replay: status of a second exchange | |
| Unassigned user with "assignment required": callback error and `AADSTS` code | |
| User assigned without role: claim shape (absent / empty) and prototype mapping result | |
| Entra app-role manifest snippet that worked | |

## Decision

(empty)

- Rule for both roles present (prototype: Admin wins):
- Rejection behaviour and message for a token without a usable role:
- Session lifetime relative to the ID token lifetime:
- Whether `groups` is needed (expected: no):

## Deviations from the design

(empty)
