"""OpenID Connect sign-in (authorization code flow with PKCE, state and nonce).

Authlib builds the authorization URL and performs the token request; the ID token signature and
claims are verified here with PyJWT against the provider's JWKS. The login state (state, nonce,
PKCE verifier, return path) travels in a short-lived encrypted cookie, so no server memory is needed.

Entra ID: ``SECURESCAN_OIDC_ISSUER=https://login.microsoftonline.com/<tenant id>/v2.0``. The ID token
must carry the ``roles`` claim (app roles ``Admin`` and ``Analyst``). The dev provider is
``ghcr.io/navikt/mock-oauth2-server`` (deploy/compose.dev.yaml).
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client

from securescan.config import Settings, get_settings
from securescan.security.secrets import SecretsError, decrypt_secret, encrypt_secret

LOGIN_COOKIE = "securescan_oidc"
LOGIN_COOKIE_PATH = "/api/v1/auth"
LOGIN_COOKIE_MAX_AGE = 600
LOGIN_CONTEXT = "oidc-login"
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "ES256")
METADATA_TTL = 3600.0


class OidcError(Exception):
    """Sign-in failed (provider error, bad state, invalid token). The message is safe to show."""


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True)
class LoginState:
    state: str
    nonce: str
    code_verifier: str
    next_path: str = "/"


@dataclass(frozen=True)
class Identity:
    oid: str
    name: str | None
    email: str | None
    upn: str | None
    roles: list[str] = field(default_factory=list)


def safe_next_path(value: str | None) -> str:
    """Only same-site relative paths are allowed as the post-login destination."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ch in value for ch in ("\r", "\n")):
        return "/"
    return value


def seal_login_state(state: LoginState) -> str:
    payload = json.dumps(
        {"s": state.state, "n": state.nonce, "v": state.code_verifier, "p": state.next_path, "t": int(time.time())}
    )
    return encrypt_secret(payload, LOGIN_CONTEXT)


def unseal_login_state(token: str, *, now: float | None = None) -> LoginState:
    try:
        data = json.loads(decrypt_secret(token, LOGIN_CONTEXT))
        issued = int(data["t"])
        state = LoginState(data["s"], data["n"], data["v"], safe_next_path(data.get("p")))
    except (SecretsError, ValueError, KeyError, TypeError) as exc:
        raise OidcError("The sign-in session is invalid or has expired. Try again.") from exc
    if (now if now is not None else time.time()) - issued > LOGIN_COOKIE_MAX_AGE:
        raise OidcError("The sign-in session has expired. Try again.")
    return state


def new_login_state(next_path: str | None) -> LoginState:
    return LoginState(
        state=secrets.token_urlsafe(24),
        nonce=secrets.token_urlsafe(24),
        code_verifier=secrets.token_urlsafe(64),
        next_path=safe_next_path(next_path),
    )


def identity_from_claims(claims: dict[str, Any], roles_claim: str = "roles") -> Identity:
    """Map ID token claims to an identity. ``oid`` (Entra) is preferred over ``sub``."""
    oid = claims.get("oid") or claims.get("sub")
    if not oid:
        raise OidcError("The identity provider did not return a user id.")
    raw_roles = claims.get(roles_claim) or []
    if isinstance(raw_roles, str):
        raw_roles = [raw_roles]
    roles = [str(r) for r in raw_roles] if isinstance(raw_roles, (list, tuple)) else []
    upn = claims.get("preferred_username") or claims.get("upn")
    email = claims.get("email") or (upn if upn and "@" in str(upn) else None)
    name = claims.get("name") or upn
    return Identity(
        oid=str(oid),
        name=str(name) if name else None,
        email=str(email) if email else None,
        upn=str(upn) if upn else None,
        roles=roles,
    )


def verify_id_token(
    id_token: str, jwks: dict[str, Any], *, issuer: str, client_id: str, nonce: str
) -> dict[str, Any]:
    """Verify signature, issuer, audience, expiry and nonce of an ID token; return its claims."""
    try:
        header = jwt.get_unverified_header(id_token)
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise OidcError("The ID token uses an unsupported signing algorithm.")
        kid = header.get("kid")
        keys = [k for k in jwks.get("keys", []) if kid is None or k.get("kid") == kid]
        if not keys:
            raise OidcError("The ID token signing key is not known (kid).")
        key = jwt.PyJWK(keys[0]).key
        claims: dict[str, Any] = jwt.decode(
            id_token,
            key,
            algorithms=[alg],
            audience=client_id,
            issuer=issuer,
            leeway=60,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError("The ID token could not be verified.") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("The ID token nonce does not match.")
    return claims


class OidcClient:
    """Talks to the identity provider. Create one per request with the shared HTTP client."""

    _metadata: OidcMetadata | None = None
    _metadata_at: float = 0.0
    _jwks: dict[str, Any] | None = None
    _jwks_at: float = 0.0

    def __init__(self, settings: Settings | None = None, http: httpx.AsyncClient | None = None) -> None:
        self.settings = settings or get_settings()
        self._http = http

    def _client(self) -> httpx.AsyncClient:
        return self._http or httpx.AsyncClient(timeout=10.0)

    async def _get_json(self, url: str) -> dict[str, Any]:
        client = self._client()
        try:
            response = await client.get(url)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return data
        except (httpx.HTTPError, ValueError) as exc:
            raise OidcError("The identity provider could not be reached.") from exc
        finally:
            if self._http is None:
                await client.aclose()

    async def metadata(self) -> OidcMetadata:
        cls = type(self)
        if cls._metadata is not None and time.monotonic() - cls._metadata_at < METADATA_TTL:
            return cls._metadata
        issuer = self.settings.oidc_issuer.rstrip("/")
        if not issuer:
            raise OidcError("Sign-in is not configured (SECURESCAN_OIDC_ISSUER is empty).")
        doc = await self._get_json(issuer + "/.well-known/openid-configuration")
        try:
            meta = OidcMetadata(
                issuer=str(doc["issuer"]),
                authorization_endpoint=str(doc["authorization_endpoint"]),
                token_endpoint=str(doc["token_endpoint"]),
                jwks_uri=str(doc["jwks_uri"]),
            )
        except KeyError as exc:
            raise OidcError("The identity provider metadata is incomplete.") from exc
        cls._metadata, cls._metadata_at = meta, time.monotonic()
        return meta

    async def jwks(self, *, force: bool = False) -> dict[str, Any]:
        cls = type(self)
        if not force and cls._jwks is not None and time.monotonic() - cls._jwks_at < METADATA_TTL:
            return cls._jwks
        meta = await self.metadata()
        keys = await self._get_json(meta.jwks_uri)
        cls._jwks, cls._jwks_at = keys, time.monotonic()
        return keys

    def _oauth(self) -> AsyncOAuth2Client:
        s = self.settings
        return AsyncOAuth2Client(
            client_id=s.oidc_client_id,
            client_secret=s.oidc_client_secret or None,
            scope=s.oidc_scopes,
            redirect_uri=s.oidc_redirect_uri,
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_post",  # noqa: S106 - a method name
            timeout=10.0,
        )

    async def authorization_url(self, login: LoginState) -> str:
        meta = await self.metadata()
        async with self._oauth() as oauth:
            url, _ = oauth.create_authorization_url(
                meta.authorization_endpoint,
                state=login.state,
                nonce=login.nonce,
                code_verifier=login.code_verifier,
                response_mode="query",
            )
        return str(url)

    async def complete(self, code: str, login: LoginState) -> Identity:
        """Exchange the code, verify the ID token and return the identity."""
        meta = await self.metadata()
        try:
            async with self._oauth() as oauth:
                token = await oauth.fetch_token(
                    meta.token_endpoint,
                    grant_type="authorization_code",
                    code=code,
                    code_verifier=login.code_verifier,
                    redirect_uri=self.settings.oidc_redirect_uri,
                )
        except Exception as exc:  # noqa: BLE001 - authlib raises several error types
            raise OidcError("The identity provider rejected the sign-in code.") from exc
        id_token = token.get("id_token")
        if not id_token:
            raise OidcError("The identity provider returned no ID token.")
        try:
            claims = verify_id_token(
                id_token,
                await self.jwks(),
                issuer=meta.issuer,
                client_id=self.settings.oidc_client_id,
                nonce=login.nonce,
            )
        except OidcError:
            # The signing keys may have rotated: refetch once.
            claims = verify_id_token(
                id_token,
                await self.jwks(force=True),
                issuer=meta.issuer,
                client_id=self.settings.oidc_client_id,
                nonce=login.nonce,
            )
        return identity_from_claims(claims, self.settings.oidc_roles_claim)
