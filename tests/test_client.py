from urllib.parse import parse_qs, urlparse

import pytest

from oidcutils.client import GrantError, OIDCClient


class RefusingOAuthClient:
    """Stands in for authlib, which returns an OAuth2 error rather than raising."""

    def __init__(self, body: dict) -> None:
        self._body = body

    async def fetch_token(self, *args, **kwargs) -> dict:
        return self._body


def _client(body: dict) -> OIDCClient:
    client = OIDCClient(
        issuer="https://id.example.com",
        client_id="my-app",
        client_secret="secret",
        redirect_uri="https://my-app.example.com/auth/callback",
    )
    client._metadata = {"token_endpoint": "https://id.example.com/token"}
    client._build_oauth_client = lambda: RefusingOAuthClient(body)  # type: ignore[method-assign]
    return client


@pytest.mark.asyncio
async def test_a_refused_refresh_grant_names_the_refusal():
    client = _client({"error": "unsupported_grant_type"})

    with pytest.raises(GrantError) as raised:
        await client.refresh("a-refresh-token")

    assert "unsupported_grant_type" in str(raised.value)


@pytest.mark.asyncio
async def test_a_refused_code_exchange_names_the_refusal():
    client = _client({"error": "invalid_grant", "error_description": "code already used"})

    with pytest.raises(GrantError) as raised:
        await client.exchange_code("a-code")

    assert "invalid_grant" in str(raised.value)
    assert "code already used" in str(raised.value)


@pytest.mark.asyncio
async def test_a_refusal_in_another_shape_still_says_what_the_server_sent():
    client = _client({"detail": "Unsupported grant_type: refresh_token"})

    with pytest.raises(GrantError) as raised:
        await client.refresh("a-refresh-token")

    assert "Unsupported grant_type" in str(raised.value)


@pytest.mark.asyncio
async def test_an_empty_refusal_still_raises():
    client = _client({})

    with pytest.raises(GrantError):
        await client.refresh("a-refresh-token")


@pytest.mark.asyncio
async def test_a_token_response_is_returned_as_a_token_set():
    client = _client({"access_token": "abc", "refresh_token": "def", "scope": "openid"})

    token_set = await client.exchange_code("a-code")

    assert token_set.access_token == "abc"
    assert token_set.refresh_token == "def"


class RecordingOAuthClient(RefusingOAuthClient):
    """Answers with a token and keeps what it was asked to send."""

    def __init__(self, body: dict) -> None:
        super().__init__(body)
        self.sent: dict = {}

    async def fetch_token(self, *args, **kwargs) -> dict:
        self.sent = kwargs
        return self._body


def _discovered() -> OIDCClient:
    client = OIDCClient(
        issuer="https://id.example.com",
        client_id="my-app",
        client_secret="secret",
        redirect_uri="https://my-app.example.com/auth/callback",
    )
    client._metadata = {
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
    }
    return client


@pytest.mark.asyncio
async def test_an_authorization_request_carries_pkce_state_and_nonce():
    started = await _discovered().authorization_request()

    query = parse_qs(urlparse(started.url).query)
    assert query["state"] == [started.state]
    assert query["nonce"] == [started.nonce]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"][0] != started.code_verifier
    assert started.code_verifier not in started.url


@pytest.mark.asyncio
async def test_each_authorization_request_has_its_own_secrets():
    client = _discovered()

    first = await client.authorization_request()
    second = await client.authorization_request()

    assert first.state != second.state
    assert first.nonce != second.nonce
    assert first.code_verifier != second.code_verifier


@pytest.mark.asyncio
async def test_the_code_verifier_is_sent_with_the_exchange():
    client = _discovered()
    oauth = RecordingOAuthClient({"access_token": "abc"})
    client._build_oauth_client = lambda: oauth  # type: ignore[method-assign]

    await client.exchange_code("a-code", code_verifier="v-1")

    assert oauth.sent["code_verifier"] == "v-1"


@pytest.mark.asyncio
async def test_an_exchange_without_a_verifier_sends_none():
    client = _discovered()
    oauth = RecordingOAuthClient({"access_token": "abc"})
    client._build_oauth_client = lambda: oauth  # type: ignore[method-assign]

    await client.exchange_code("a-code")

    assert "code_verifier" not in oauth.sent
