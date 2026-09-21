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
