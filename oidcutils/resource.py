from typing import Any

import httpx
from joserfc import jwt
from joserfc.errors import (
    BadSignatureError,
    DecodeError,
    ExpiredTokenError,
    InvalidClaimError,
    InvalidKeyIdError,
    JoseError,
)
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from oidcutils.claims import ClaimMapper, DefaultClaimMapper
from oidcutils.principal import Principal


class TokenError(Exception):
    pass


class TokenValidator:
    """Validates JWT access tokens using OIDC discovery and JWKS."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
        claim_mapper: ClaimMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._algorithms = algorithms or ["RS256", "ES256"]
        self._claim_mapper = claim_mapper or DefaultClaimMapper()
        self._client = http_client
        self._jwks: dict[str, Any] | None = None
        self._jwks_uri: str | None = None

    async def _ensure_jwks_uri(self) -> str:
        if self._jwks_uri is not None:
            return self._jwks_uri

        client = self._client or httpx.AsyncClient()
        url = f"{self._issuer}/.well-known/openid-configuration"
        response = await client.get(url)
        response.raise_for_status()

        data = response.json()
        discovered_issuer = data["issuer"].rstrip("/")
        if discovered_issuer != self._issuer:
            raise TokenError(f"Issuer mismatch: expected {self._issuer}, got {discovered_issuer}")

        self._jwks_uri = data["jwks_uri"]
        return self._jwks_uri

    async def _get_keyset(self, force_refresh: bool = False) -> KeySet:
        if self._jwks is not None and not force_refresh:
            return KeySet.import_key_set(self._jwks)  # type: ignore[arg-type]

        jwks_uri = await self._ensure_jwks_uri()
        client = self._client or httpx.AsyncClient()
        response = await client.get(jwks_uri)
        response.raise_for_status()

        self._jwks = response.json()
        return KeySet.import_key_set(self._jwks)  # type: ignore[arg-type]

    async def validate_token(self, token: str) -> Principal:
        claims_registry = JWTClaimsRegistry(
            iss={"essential": True, "value": self._issuer},
            aud={"essential": True, "value": self._audience},
            exp={"essential": True},
            sub={"essential": True},
        )

        try:
            keyset = await self._get_keyset()
            decoded = jwt.decode(token, keyset, algorithms=self._algorithms)
            claims_registry.validate(decoded.claims)
        except ExpiredTokenError as exc:
            raise TokenError("Token has expired") from exc
        except (BadSignatureError, DecodeError, InvalidKeyIdError):
            try:
                keyset = await self._get_keyset(force_refresh=True)
                decoded = jwt.decode(token, keyset, algorithms=self._algorithms)
                claims_registry.validate(decoded.claims)
            except (BadSignatureError, DecodeError, InvalidKeyIdError) as exc:
                raise TokenError(f"Invalid token signature: {exc}") from exc
            except ExpiredTokenError as exc:
                raise TokenError("Token has expired") from exc
            except InvalidClaimError as exc:
                raise TokenError(f"Invalid claim: {exc}") from exc
            except JoseError as exc:
                raise TokenError(f"Invalid token: {exc}") from exc
        except InvalidClaimError as exc:
            raise TokenError(f"Invalid claim: {exc}") from exc
        except JoseError as exc:
            # Everything else the library can raise about a token, caught by
            # its base class rather than by name. A token carrying an
            # algorithm we do not accept raises UnsupportedAlgorithmError,
            # which named clauses missed: it left an unauthenticated caller
            # able to raise an unhandled exception on every request, and made
            # a rejected token look like a server fault rather than a refusal.
            #
            # Deliberately not retried against a refreshed key set. A key
            # rotation cannot make an unacceptable algorithm acceptable, so a
            # refresh here would fetch the JWKS for every malformed token that
            # arrived.
            raise TokenError(f"Invalid token: {exc}") from exc

        return self._claim_mapper.map(decoded.claims)
