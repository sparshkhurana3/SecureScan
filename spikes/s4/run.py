#!/usr/bin/env python3
"""Spike S4: Entra ID (or the mock provider) OIDC authorization-code flow with PKCE and the `roles` claim.

Run (repository root, on the machine whose browser can reach the redirect URI):

    OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0 \
    OIDC_CLIENT_ID=<application (client) id> \
    OIDC_CLIENT_SECRET_FILE=deploy/secrets/oidc_client_secret \
    uv run --project backend python spikes/s4/run.py --expect admin

Environment variables
    OIDC_ISSUER            issuer URL; discovery is read from <issuer>/.well-known/openid-configuration (required)
    OIDC_CLIENT_ID         client id (required)
    OIDC_CLIENT_SECRET     client secret, or OIDC_CLIENT_SECRET_FILE with a path (required, one of the two)
    S4_REDIRECT_URI        default https://securescan.localtest.me:8443/api/v1/auth/callback (must be registered in Entra;
                           for an http://localhost:<port>/... URI no certificate is needed)
    S4_TLS_CERT, S4_TLS_KEY  certificate for an https redirect URI (default deploy/secrets/tls/server.crt|key from `dev.py certs`)
    S4_BIND                address the callback listener binds to (default 127.0.0.1; *.localtest.me resolves to 127.0.0.1)
    S4_SCOPES              default "openid profile email"
    S4_TIMEOUT             seconds to wait for the browser (default 300)
    S4_VERIFY              path of a CA bundle for the issuer (mock provider with a private CA), or "0" to skip (not for Entra)
    S4_SHOW_CLAIMS         1 = print identifying claim values (sub, oid, email, name, ...); default prints only their shape
    S4_AUTH_METHOD         token endpoint auth: client_secret_basic (default) or client_secret_post

Arguments
    --expect any|admin|analyst|norole|denied
        any      the token must carry Admin and/or Analyst (default)
        admin    must carry Admin           analyst  must carry Analyst
        norole   sign-in succeeds but no usable role: SecureScan must reject (the prototype below returns None)
        denied   the identity provider itself must refuse the sign-in (Entra "assignment required": AADSTS50105)
    --paste  do not start a listener; print the URL, then paste the full redirect URL from the browser's address bar
             (use when the browser is on another machine; the page will not load, the address bar is enough)

Run it once per case: a user with the Admin role, one with Analyst, one with both, one assigned without a role (norole),
one not assigned at all with "assignment required" on (denied). Each run prints a "Recorded facts" table for the findings file.
Exit code 0 only when the result matches --expect.
"""

from __future__ import annotations

import argparse
import http.server
import json
import ssl
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import spikelib  # noqa: E402
from spikelib import Spike, SpikeFailure, env  # noqa: E402

HERE = Path(__file__).resolve().parent
IDENTIFYING = {"sub", "oid", "tid", "email", "preferred_username", "name", "unique_name", "upn", "given_name",
               "family_name", "aio", "uti", "rh", "sid", "login_hint", "xms_edov", "xms_pdl", "xms_tpl", "xms_st"}


def role_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    """Prototype of the mapping M2 implements in securescan/auth/roles.py.

    Admin wins over Analyst; anything else (including no `roles` claim) means: refuse the sign-in.
    """
    raw = claims.get("roles")
    roles = raw if isinstance(raw, list) else ([raw] if isinstance(raw, str) else [])
    if "Admin" in roles:
        return "Admin"
    if "Analyst" in roles:
        return "Analyst"
    return None


def describe(name: str, value: Any, show: bool) -> str:
    if name in IDENTIFYING and not show:
        return "%s(len=%d)" % (type(value).__name__, len(str(value)))
    if isinstance(value, list):
        if name == "groups" and not show:
            return "list(%d group ids)" % len(value)
        return json.dumps(value)
    return json.dumps(value)


class CallbackServer:
    """One-shot HTTP(S) listener that captures the first request to the redirect path."""

    def __init__(self, redirect_uri: str, bind: str, certfile: Optional[str], keyfile: Optional[str]) -> None:
        parts = urlsplit(redirect_uri)
        self.path = parts.path
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.result = None  # type: Optional[str]
        self.event = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if urlsplit(self.path).path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.result = "%s://%s%s" % (parts.scheme, parts.netloc, self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"SecureScan spike S4: callback received. You can close this tab.\n")
                outer.event.set()

            def log_message(self, fmt: str, *args: Any) -> None:  # keep the query string (code, state) out of logs
                return

        self.httpd = http.server.HTTPServer((bind, self.port), Handler)
        if parts.scheme == "https":
            if not certfile or not keyfile:
                raise SpikeFailure("https redirect URI needs S4_TLS_CERT and S4_TLS_KEY")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def body(spike: Spike) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--expect", default="any", choices=["any", "admin", "analyst", "norole", "denied"])
    parser.add_argument("--paste", action="store_true")
    parser.add_argument("--open-browser", action="store_true")
    args = parser.parse_args()

    from authlib.common.security import generate_token
    from authlib.integrations.httpx_client import OAuth2Client
    import jwt

    issuer = (env("OIDC_ISSUER", required=True) or "").rstrip("/")
    client_id = env("OIDC_CLIENT_ID", required=True) or ""
    secret = env("OIDC_CLIENT_SECRET", required=True) or ""
    redirect_uri = env("S4_REDIRECT_URI", "https://securescan.localtest.me:8443/api/v1/auth/callback") or ""
    scopes = env("S4_SCOPES", "openid profile email") or ""
    timeout = float(env("S4_TIMEOUT", "300") or "300")
    show_claims = (env("S4_SHOW_CLAIMS", "0") or "0") == "1"
    verify_setting = env("S4_VERIFY", "1")
    verify = True  # type: Any
    if verify_setting == "0":
        verify = False
        spike.warn("TLS verification of the identity provider is OFF (S4_VERIFY=0); never do this against Entra")
    elif verify_setting and verify_setting != "1":
        verify = verify_setting
    auth_method = env("S4_AUTH_METHOD", "client_secret_basic") or "client_secret_basic"
    repo = spikelib.REPO_ROOT
    certfile = env("S4_TLS_CERT", str(repo / "deploy" / "secrets" / "tls" / "server.crt"))
    keyfile = env("S4_TLS_KEY", str(repo / "deploy" / "secrets" / "tls" / "server.key"))
    http_client = spikelib.make_http_client(verify=verify)
    spike.fact("issuer", issuer)
    spike.fact("redirect_uri", redirect_uri)
    spike.fact("scopes_requested", scopes)
    spike.fact("expectation_for_this_run", args.expect)

    # ---- discovery ---------------------------------------------------------------------------------------
    spike.step("OIDC discovery")
    r = spike.http(http_client, "GET", issuer + "/.well-known/openid-configuration", expect=[200], max_body=2500)
    disc = r.json()
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"):
        spike.fact("discovery.%s" % key, disc.get(key, "absent"))
    spike.fact("discovery.code_challenge_methods_supported", disc.get("code_challenge_methods_supported", "absent"))
    spike.fact("discovery.id_token_signing_alg_values_supported", disc.get("id_token_signing_alg_values_supported", "absent"))
    spike.fact("discovery.token_endpoint_auth_methods_supported", disc.get("token_endpoint_auth_methods_supported", "absent"))
    spike.fact("discovery.claims_supported_has_roles", "roles" in (disc.get("claims_supported") or []))
    spike.expect("S256" in (disc.get("code_challenge_methods_supported") or ["S256"]),
                 "the provider supports PKCE S256 (or does not advertise methods)")

    # ---- authorization request -----------------------------------------------------------------------------------
    spike.step("Authorization request (authorization code + PKCE S256 + nonce)")
    verifier = generate_token(64)
    nonce = generate_token(32)
    oauth = OAuth2Client(
        client_id=client_id, client_secret=secret, scope=scopes, redirect_uri=redirect_uri,
        code_challenge_method="S256", token_endpoint_auth_method=auth_method, verify=verify,
    )
    auth_url, state = oauth.create_authorization_url(disc["authorization_endpoint"], code_verifier=verifier, nonce=nonce)
    spike.fact("authorization_url_params", ",".join(sorted(parse_qs(urlsplit(auth_url).query).keys())))
    spike.out("Open this URL in a browser and sign in as the test user for the case '%s':" % args.expect)
    spike.out("")
    spike.out(auth_url)
    spike.out("")
    response_url = None  # type: Optional[str]
    if args.paste:
        response_url = input("Paste the full redirect URL from the address bar: ").strip()
    else:
        server = CallbackServer(redirect_uri, env("S4_BIND", "127.0.0.1") or "127.0.0.1", certfile, keyfile)
        server.start()
        try:
            if args.open_browser:
                webbrowser.open(auth_url)
            spike.out("Waiting up to %.0f s for the callback on %s ..." % (timeout, redirect_uri))
            if not server.event.wait(timeout):
                raise SpikeFailure("no callback within %.0f s" % timeout)
            response_url = server.result
        finally:
            server.stop()
    parts = urlsplit(response_url or "")
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    spike.fact("callback_query_keys", ",".join(sorted(query)))

    # ---- denied by the identity provider ------------------------------------------------------------------------------
    if "error" in query:
        description = query.get("error_description", "").replace("\r", " ").replace("\n", " ")
        spike.fact("callback_error", query["error"])
        spike.fact("callback_error_description", description[:300])
        if args.expect == "denied":
            spike.expect(True, "the identity provider refused the sign-in as expected (%s)" % query["error"])
            spike.fact("assignment_required_error_code_seen", "AADSTS50105" in description)
            return 0
        raise SpikeFailure("the provider returned an error but --expect is %s: %s %s" % (args.expect, query["error"], description[:200]))
    if args.expect == "denied":
        raise SpikeFailure("--expect denied, but the sign-in succeeded: 'Assignment required' is not effective for this user")
    spike.expect(query.get("state") == state, "state parameter matches")
    code = query.get("code")
    spike.expect(bool(code), "authorization code present (length %d)" % len(code or ""))

    # ---- token exchange ----------------------------------------------------------------------------------------------------
    spike.step("Token exchange")
    started = time.monotonic()
    token = oauth.fetch_token(
        disc["token_endpoint"], grant_type="authorization_code", code=code, code_verifier=verifier,
        redirect_uri=redirect_uri,
    )
    spike.out("token endpoint answered in %d ms; response keys: %s" % ((time.monotonic() - started) * 1000, sorted(token.keys())))
    spike.fact("token_response_keys", ",".join(sorted(token.keys())))
    spike.fact("token_type", token.get("token_type"))
    spike.fact("scope_returned", token.get("scope"))
    spike.fact("expires_in", token.get("expires_in"))
    spike.fact("refresh_token_present", "refresh_token" in token)
    spike.fact("id_token_length", len(token.get("id_token", "")))
    spike.expect("id_token" in token, "an id_token came back")
    # replay protection of the code
    r = http_client.post(disc["token_endpoint"], data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier,
        "client_id": client_id, "client_secret": secret})
    spike.fact("code_replay_status", r.status_code)

    # ---- ID token ----------------------------------------------------------------------------------------------------------------
    spike.step("Validate and decode the ID token")
    id_token = token["id_token"]
    header = jwt.get_unverified_header(id_token)
    spike.fact("id_token_header", {k: header[k] for k in header if k in ("alg", "typ", "kid")} if not show_claims else header)
    jwks = http_client.get(disc["jwks_uri"]).json()
    candidates = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")]
    spike.expect(len(candidates) == 1, "exactly one signing key with kid %s in the JWKS (%d keys published)" % (header.get("kid"), len(jwks.get("keys", []))))
    signing_key = jwt.PyJWK(candidates[0]).key
    claims = jwt.decode(
        id_token, signing_key, algorithms=["RS256", "ES256", "PS256"], audience=client_id, leeway=60,
        options={"require": ["exp", "iat", "aud", "iss"], "verify_iss": False},
    )
    spike.fact("iss_matches_configured_issuer", claims.get("iss") == issuer)
    spike.fact("iss_value_shape", claims.get("iss") if show_claims else (claims.get("iss", "")[:32] + "..."))
    spike.expect(claims.get("nonce") == nonce, "nonce matches")
    spike.out("Claims (identifying values hidden unless S4_SHOW_CLAIMS=1):")
    spike.out("")
    spike.out("| claim | type | value |")
    spike.out("| --- | --- | --- |")
    for name in sorted(claims):
        spike.out("| %s | %s | %s |" % (name, type(claims[name]).__name__, describe(name, claims[name], show_claims)))
    spike.fact("claims_present", ",".join(sorted(claims)))
    spike.fact("ver_claim", claims.get("ver", "absent"))
    spike.fact("token_lifetime_seconds", int(claims.get("exp", 0)) - int(claims.get("iat", 0)))
    spike.fact("roles_claim_present", "roles" in claims)
    spike.fact("roles_claim_type", type(claims.get("roles")).__name__)
    spike.fact("roles_claim_value", claims.get("roles", "absent"))
    spike.fact("groups_claim_present", "groups" in claims)
    spike.fact("groups_overage_markers", {k: claims[k] for k in ("hasgroups", "_claim_names", "_claim_sources") if k in claims} or "none")
    spike.fact("idtyp_claim", claims.get("idtyp", "absent"))
    spike.fact("wids_claim", claims.get("wids", "absent"))
    mapped = role_from_claims(claims)
    spike.fact("prototype_role_mapping_result", mapped)

    # ---- expectation -----------------------------------------------------------------------------------------------------------------
    spike.step("Check against --expect %s" % args.expect)
    roles = claims.get("roles") if isinstance(claims.get("roles"), list) else []
    if args.expect == "admin":
        spike.expect("Admin" in roles, "roles contains Admin (roles=%s)" % roles)
    elif args.expect == "analyst":
        spike.expect("Analyst" in roles, "roles contains Analyst (roles=%s)" % roles)
    elif args.expect == "any":
        spike.expect(mapped is not None, "roles contains Admin and/or Analyst (roles=%s)" % roles)
    elif args.expect == "norole":
        spike.expect(mapped is None, "no usable role: SecureScan must reject this sign-in (roles=%s)" % roles)
    if "Admin" in roles and "Analyst" in roles:
        spike.note("both roles present: the prototype mapping gives Admin; record this as the rule in the findings file")
    return 0


def main() -> int:
    spike = Spike("s4", "S4 Entra ID OIDC with app roles", HERE)
    return spikelib.run_spike(spike, body)


if __name__ == "__main__":
    sys.exit(main())
