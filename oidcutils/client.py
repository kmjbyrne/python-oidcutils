from dataclasses import dataclass, field
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client


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

    async def exchange_code(self, code: str) -> TokenSet:
        """Exchange an authorization code for tokens."""
        metadata = await self._discover()
        oauth = self._build_oauth_client()
        token = await oauth.fetch_token(
            metadata["token_endpoint"],
            code=code,
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
        return TokenSet(
            access_token=token["access_token"],
            token_type=token.get("token_type", "Bearer"),
            refresh_token=token.get("refresh_token"),
            expires_at=token.get("expires_at"),
            id_token=token.get("id_token"),
            scope=token.get("scope", ""),
            raw=token,
        )
