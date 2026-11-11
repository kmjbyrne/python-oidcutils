import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client


class GrantError(Exception):
    """The identity server refused to issue tokens.

    Distinct from ``TokenError``, which means a token was presented and did
    not validate. This means no token was issued at all: a code already
    redeemed, a refresh token the server does not recognise, client
    credentials it rejects, or a grant it does not implement.
    """


@dataclass
class TokenSet:
    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_at: float | None = None
    id_token: str | None = None
    scope: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        import time

        return time.time() >= self.expires_at


@dataclass(frozen=True)
class AuthorizationRequest:
    """One sign-in round trip: where to send the browser, and what to keep.

    ``state``, ``nonce`` and ``code_verifier`` are this round trip's secrets.
    Keep all three until the callback, somewhere only this browser's request
    can reach, such as a short-lived httpOnly cookie. Check ``state`` against
    the callback's, pass ``code_verifier`` to ``exchange_code``, and pass
    ``nonce`` to ``TokenValidator.validate_token`` with the ID token.
    """

    url: str
    state: str
    nonce: str
    code_verifier: str


class OIDCClient:
    """Handles authorization code flow, token exchange, and refresh."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes or ["openid", "profile", "email"]
        self._http_client = http_client
        self._metadata: dict[str, Any] | None = None

    async def _discover(self) -> dict[str, Any]:
        if self._metadata is not None:
            return self._metadata

        client = self._http_client or httpx.AsyncClient()
        url = f"{self._issuer}/.well-known/openid-configuration"
        response = await client.get(url)
        response.raise_for_status()

        self._metadata = response.json()
        return self._metadata

    def _build_oauth_client(self) -> AsyncOAuth2Client:
        """Return a client for the token endpoint.

        Carries the transport it was given, so an issuer that is not on the
        network is reachable. A mounted dev provider is the case: it listens on
        no port, and without this the code exchange tries to resolve its issuer
        as a hostname and fails where discovery had just succeeded.
        """
        transport = getattr(self._http_client, "_transport", None)
        return AsyncOAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret,
            redirect_uri=self._redirect_uri,
            scope=" ".join(self._scopes),
            transport=transport,
        )

    async def authorization_url(self, state: str | None = None) -> tuple[str, str]:
        """Return (url, state) to redirect the user to the IdP."""
        metadata = await self._discover()
        oauth = self._build_oauth_client()
        url, state = oauth.create_authorization_url(
            metadata["authorization_endpoint"],
            state=state,
        )
        return url, state

    async def authorization_request(self) -> AuthorizationRequest:
        """Start a sign-in with PKCE (S256) and a nonce.

        Prefer this to ``authorization_url``. The code challenge binds the code
        to this round trip, so a code intercepted on the way back cannot be
        redeemed without the verifier. The nonce does the same for the ID
        token, so one minted for another sign-in is refused.
        """
        metadata = await self._discover()
        oauth = self._build_oauth_client()
        oauth.code_challenge_method = "S256"
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(48)
        url, state = oauth.create_authorization_url(
            metadata["authorization_endpoint"],
            state=secrets.token_urlsafe(32),
            code_verifier=code_verifier,
            nonce=nonce,
        )
        return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=code_verifier)

    async def exchange_code(self, code: str, code_verifier: str | None = None) -> TokenSet:
        """Exchange an authorization code for tokens.

        Pass the ``code_verifier`` from ``authorization_request``. A sign-in
        started with ``authorization_url`` has none.
        """
        metadata = await self._discover()
        oauth = self._build_oauth_client()
        extra = {"code_verifier": code_verifier} if code_verifier else {}
        token = await oauth.fetch_token(
            metadata["token_endpoint"],
            code=code,
            **extra,
        )
        return self._to_token_set(token)

    async def refresh(self, refresh_token: str) -> TokenSet:
        """Use a refresh token to get a new token set."""
        metadata = await self._discover()
        oauth = self._build_oauth_client()
        token = await oauth.fetch_token(
            metadata["token_endpoint"],
            grant_type="refresh_token",
            refresh_token=refresh_token,
        )
        return self._to_token_set(token)

    def _to_token_set(self, token: dict[str, Any]) -> TokenSet:
        # An OAuth2 error is a 400 carrying a JSON body, which authlib returns
        # rather than raising on, so it arrives here looking like a token.
        # Indexing it raises KeyError, which names neither the grant that
        # failed nor the server that refused it.
        if "access_token" not in token:
            # RFC 6749 says `error` with an optional `error_description`, but a
            # server that answers some other shape still has to produce a
            # message somebody can act on, so fall back to what it did send.
            error = token.get("error")
            if error:
                description = token.get("error_description")
                detail = f"{error}: {description}" if description else error
            else:
                detail = str(token) if token else "the response carried no body"
            raise GrantError(f"The identity server issued no token, {detail}")

        return TokenSet(
            access_token=token["access_token"],
            token_type=token.get("token_type", "Bearer"),
            refresh_token=token.get("refresh_token"),
            expires_at=token.get("expires_at"),
            id_token=token.get("id_token"),
            scope=token.get("scope", ""),
            raw=token,
        )
