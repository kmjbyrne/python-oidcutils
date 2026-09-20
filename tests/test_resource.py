import base64
import json
import time
from typing import Any

import httpx
import pytest
from joserfc import jwt as jose_jwt
from joserfc.jwk import OctKey, RSAKey

from oidcutils.resource import TokenError, TokenValidator

ISSUER = "https://id.example.com"
AUDIENCE = "my-api"


def _generate_key() -> RSAKey:
    return RSAKey.generate_key(2048)


SIGNING_KEY = _generate_key()


def _public_jwks(key: RSAKey | None = None) -> dict[str, Any]:
    k = key or SIGNING_KEY
    pub = k.as_dict(is_private=False)
    pub["kid"] = "test-key-1"
    return {"keys": [pub]}


def _make_token(
    claims: dict[str, Any] | None = None,
    key: RSAKey | None = None,
    kid: str = "test-key-1",
) -> str:
    signing_key = key or SIGNING_KEY
    header = {"alg": "RS256", "kid": kid}
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        **(claims or {}),
    }
    return jose_jwt.encode(header, payload, signing_key)


class FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, jwks: dict[str, Any] | None = None) -> None:
        self._jwks = jwks or _public_jwks()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                    "userinfo_endpoint": f"{ISSUER}/userinfo",
                },
            )
        if url.endswith("/jwks.json"):
            return httpx.Response(200, json=self._jwks)
        return httpx.Response(404)


@pytest.fixture
def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=FakeTransport())


@pytest.fixture
def validator(client: httpx.AsyncClient) -> TokenValidator:
    return TokenValidator(
        issuer=ISSUER,
        audience=AUDIENCE,
        http_client=client,
    )


@pytest.mark.asyncio
async def test_valid_token(validator: TokenValidator):
    token = _make_token({"email": "user@example.com", "roles": ["admin"]})
    principal = await validator.validate_token(token)

    assert principal.subject == "user-123"
    assert principal.issuer == ISSUER
    assert principal.email == "user@example.com"
    assert principal.has_role("admin")


@pytest.mark.asyncio
async def test_expired_token(validator: TokenValidator):
    token = _make_token({"exp": int(time.time()) - 100})
    with pytest.raises(TokenError, match="expired"):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_wrong_audience(validator: TokenValidator):
    token = _make_token({"aud": "wrong-api"})
    with pytest.raises(TokenError, match="Invalid claim"):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_wrong_issuer(validator: TokenValidator):
    token = _make_token({"iss": "https://evil.example.com"})
    with pytest.raises(TokenError, match="Invalid claim"):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_an_algorithm_we_do_not_accept_is_a_token_error(validator: TokenValidator):
    """A refusal, not a server fault.

    The token is rejected either way. What matters is which exception leaves
    this method: anything that is not a TokenError reaches the caller as an
    unhandled error, so an unauthenticated request could raise one on every
    call and be answered 500 rather than 401.
    """
    secret = OctKey.import_key("k" * 32)
    token = jose_jwt.encode(
        {"alg": "HS256", "kid": "test-key-1"},
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
        },
        secret,
    )

    with pytest.raises(TokenError, match="Invalid token"):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_an_unsigned_token_is_a_token_error(validator: TokenValidator):
    """``alg: none`` is the oldest bypass attempt there is."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"test-key-1"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-123", "exp": int(time.time()) + 3600}
        ).encode()
    ).rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}."

    with pytest.raises(TokenError):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_key_rotation():
    new_key = _generate_key()
    call_count = 0
    original_jwks = _public_jwks()

    new_pub = new_key.as_dict(is_private=False)
    new_pub["kid"] = "rotated-key"
    rotated_jwks = {"keys": [*original_jwks["keys"], new_pub]}

    class RotatingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            url = str(request.url)
            if url.endswith("/.well-known/openid-configuration"):
                return httpx.Response(
                    200,
                    json={
                        "issuer": ISSUER,
                        "authorization_endpoint": f"{ISSUER}/authorize",
                        "token_endpoint": f"{ISSUER}/token",
                        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                    },
                )
            if url.endswith("/jwks.json"):
                call_count += 1
                if call_count == 1:
                    return httpx.Response(200, json=original_jwks)
                return httpx.Response(200, json=rotated_jwks)
            return httpx.Response(404)

    client = httpx.AsyncClient(transport=RotatingTransport())
    validator = TokenValidator(
        issuer=ISSUER,
        audience=AUDIENCE,
        http_client=client,
    )

    token_old = _make_token()
    principal = await validator.validate_token(token_old)
    assert principal.subject == "user-123"

    token_new = _make_token(key=new_key, kid="rotated-key")
    principal = await validator.validate_token(token_new)
    assert principal.subject == "user-123"
    assert call_count == 2


@pytest.mark.asyncio
async def test_issuer_mismatch_in_discovery():
    class BadDiscoveryTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://wrong.example.com",
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                },
            )

    client = httpx.AsyncClient(transport=BadDiscoveryTransport())
    validator = TokenValidator(issuer=ISSUER, audience=AUDIENCE, http_client=client)

    token = _make_token()
    with pytest.raises(TokenError, match="Issuer mismatch"):
        await validator.validate_token(token)
